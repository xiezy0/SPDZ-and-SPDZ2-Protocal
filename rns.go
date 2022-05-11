package spdz2

import (
	"crypto/rand"
	"math"
	"math/big"
)

// high interface in RNS domin
type RnsHigh interface {
	rns(encodeTriple *big.Int) (res *big.Int, residuSlice []*big.Int)
	rnsAddTest(encodeTriple0, encodeTriple1 *big.Int) (res *big.Int)
	rnsMultTest(encodeTriple0, encodeTriple1 *big.Int) (res *big.Int)
}

// SPDZ based RNS high interface
type RnspdzHigh interface {
	RnsHigh
}

// low interface in RNS domin
type RnsLow interface {
	RnsHigh
	genResiduSlice(encodeTriple *big.Int) (residuSlice []*big.Int)
	rnsAdd(residuSlice0 []*big.Int, residuSlice1 []*big.Int) (residuSliceAdd []*big.Int)
	rnsMult(residuSlice0 []*big.Int, residuSlice1 []*big.Int) (residuSliceMult []*big.Int)
	crt(residuSlice []*big.Int) (res *big.Int)
}

// global params of RNS params
type rnsParams struct {
	primeBit, primeNum int
	primeb             *big.Int
	primeSlice         []*big.Int
}

func rnsInit(num int, encodeTriples []*big.Int) (params rnsParams) {
	primeBit, primeNum := genPrimeParams(num, encodeTriples)
	primeSlice, primeb := genPrimeSlice(primeNum, primeBit)
	params = rnsParams{primeBit, primeNum, primeb, primeSlice}
	return
}

func rnspdzInit(num int, security int) (params rnsParams) {
	primeBit, primeNum := genPrimeParamse(num, security)
	primeSlice, primeb := genPrimeSlice(primeNum, primeBit)
	params = rnsParams{primeBit, primeNum, primeb, primeSlice}
	return
}

func (params *rnsParams) rns(encodeTriple *big.Int) (res *big.Int, residuSlice []*big.Int) {
	residuSlice = params.genResiduSlice(encodeTriple)
	res = params.crt(residuSlice)
	return
}

func (params *rnsParams) rnsAddTest(encodeTriple0, encodeTriple1 *big.Int) (res *big.Int) {
	residuSlice0 := params.genResiduSlice(encodeTriple0)
	residuSlice1 := params.genResiduSlice(encodeTriple1)
	residuSliceAdd := params.rnsAdd(residuSlice0, residuSlice1)
	res = params.crt(residuSliceAdd)
	return
}

func (params *rnsParams) rnsMultTest(encodeTriple0, encodeTriple1 *big.Int) (res *big.Int) {
	residuSlice0 := params.genResiduSlice(encodeTriple0)
	residuSlice1 := params.genResiduSlice(encodeTriple1)
	residuSliceAdd := params.rnsMult(residuSlice0, residuSlice1)
	res = params.crt(residuSliceAdd)
	return
}

// 计算剩余项
func (params *rnsParams) genResiduSlice(encodeTriple *big.Int) (residuSlice []*big.Int) {
	residuSlice = make([]*big.Int, 0)
	for _, prime := range params.primeSlice {
		residuSlice = append(residuSlice, new(big.Int).Mod(encodeTriple, prime))
	}
	return
}

// 计算rns域中的加法
func (params *rnsParams) rnsAdd(residuSlice0 []*big.Int, residuSlice1 []*big.Int) (residuSliceAdd []*big.Int) {
	residuSliceAdd = make([]*big.Int, 0)
	add := new(big.Int)
	for i, prime := range params.primeSlice {
		add.Add(residuSlice0[i], residuSlice1[i])
		residuSliceAdd = append(residuSliceAdd, new(big.Int).Mod(add, prime))
	}
	return
}

// 计算rns域中的乘法
func (params *rnsParams) rnsMult(residuSlice0 []*big.Int, residuSlice1 []*big.Int) (residuSliceMult []*big.Int) {
	residuSliceMult = make([]*big.Int, 0)
	mul := new(big.Int)
	for i, prime := range params.primeSlice {
		mul.Mul(residuSlice0[i], residuSlice1[i])
		residuSliceMult = append(residuSliceMult, new(big.Int).Mod(mul, prime))
	}
	return
}

// 中国剩余定理解密
func (params *rnsParams) crt(residuSlice []*big.Int) (res *big.Int) {
	res = new(big.Int).SetInt64(0)
	primesSliceDiv := make([]*big.Int, 0)
	primesSliceDivInv := make([]*big.Int, 0)
	xj := make([]*big.Int, 0)
	mmi := new(big.Int)
	for _, prime := range params.primeSlice {
		primesSliceDiv = append(primesSliceDiv, new(big.Int).Div(params.primeb, prime))
	}
	for i, prime := range params.primeSlice {
		primesSliceDivInv = append(primesSliceDivInv, new(big.Int).ModInverse(primesSliceDiv[i], prime))
	}
	for i, primediv := range primesSliceDiv {
		mmi.Mul(primediv, primesSliceDivInv[i])
		mmi.Mod(mmi, params.primeb)
		xj = append(xj, new(big.Int).Mul(mmi, residuSlice[i]))
	}
	for _, xjj := range xj {
		res.Add(res, xjj)
		res.Mod(res, params.primeb)
	}
	return
}

func genPrimeParamse(num int, sebit int) (primeBit, primeNum int) {
	primeBit = evaPrimesBit(num)
	primeNum = (sebit + primeBit - 1) * 3 / primeBit
	return
}

// TODO:: 改用每一方自己计算Bitlen
func genPrimeParams(num int, encodeTriples []*big.Int) (primeBit, primeNum int) {
	n := 0
	for _, triple := range encodeTriples {
		if triple.BitLen() > n {
			n = triple.BitLen()
		}
	}
	primeBit = evaPrimesBit(num)
	primeNum = (n + primeBit - 1) * 2 / primeBit
	return
}

// 生成素数
func genPrimeSlice(primeNumber int, primeBit int) (primeSlice []*big.Int, primeb *big.Int) {
	primeb = big.NewInt(1)
	primeSlice = make([]*big.Int, 0)
	for i := 0; i < primeNumber; i++ {
		primel, _ := rand.Prime(rand.Reader, primeBit)
		if InSlice(primeSlice, primel) {
			i--
		} else {
			primeSlice = append(primeSlice, primel)
			primeb.Mul(primeb, primel)
		}
	}
	return
}

// 根据计算方数量 计算每一个小素数的位数
func evaPrimesBit(num int) (res int) {
	lognum := math.Log2(float64(num))
	res = 28 - int(lognum)
	//	res = 29 -
	return
}

// 元素item是否在切片items中
func InSlice(items []*big.Int, item *big.Int) bool {
	for _, eachItem := range items {
		if eachItem.Cmp(item) == 0 {
			return true
		}
	}
	return false
}
