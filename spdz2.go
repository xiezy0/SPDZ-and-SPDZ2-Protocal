package spdz2

import (
	"crypto/rand"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"math/big"
	"sync"
	"time"
)

// the public params of SPDZ
type spdz2Params struct {
	spdzParams
	encodenum int
}

func spdz2Init(num int, security int) (params rnsParams, fprime *big.Int, wgmain sync.WaitGroup) {
	//// 2 *（2^i - 1）
	//exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(encodenum-2))-1) * 2)
	//// d = m + log2(num) + 1
	//d := security + int(math.Log2(float64(encodenum))) + 1
	//// k = d + m
	//k := new(big.Int).SetInt64(int64(d + security))
	//// 2 * k * (2^i - 1)
	//kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
	//
	//// 2 ^ (2 * k * (2^i - 1))
	//encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
	//fmt.Println(encodebase.BitLen())
	// 30000
	params = rnspdzInit(num, 30000)
	fprime, _ = rand.Prime(rand.Reader, security)
	wgmain = sync.WaitGroup{}
	wgmain.Add(num)
	return
}

func GenTriple2(num int, security int, encodenum int) float64 {
	skChan := make(chan *party, num)
	rnsparams, fprime, wgmain := spdz2Init(num, security)
	publicparams, P := dkeyGen(num)
	spdzparams := spdz2Params{spdzParams{rnsparams, publicparams, fprime}, encodenum}
	txparams := encTxInitMul(num, 7)
	Alpha := spdzparams.encodeAlpha()
	ciphertextAlpha := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(Alpha)))

	Alpha2 := spdzparams.encodeAlpha2()
	ciphertextAlpha2 := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(Alpha2)))
	fmt.Println("alpha:", Alpha)
	fmt.Println("alpha2", Alpha2)
	mutexSwitch := sync.Mutex{}
	for i := 0; i < num; i++ {
		skChan <- P[i]
	}
	// num goroutine <---> num players

	now1 := time.Now()
	for i := 0; i < num; i++ {
		go func(params spdz2Params, Id int, convSyncChan0 <-chan *party) {
			// step 1
			encodea, encodeb := params.encodeTripleab()
			// step 2
			mutexSwitch.Lock()
			ciphertexta := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(encodea)))
			ciphertextb := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(encodeb)))
			mutexSwitch.Unlock()

			ciphertextaSlice := txparams[0].encTx(num, ciphertexta)
			ciphertextbSlice := txparams[1].encTx(num, ciphertextb)
			// step 3&4
			ciphertextA := params.AddSlice(ciphertextaSlice, &mutexSwitch)
			ciphertextB := params.AddSlice(ciphertextbSlice, &mutexSwitch)
			// step 5
			AlphaAshare := params.PAngle2(ciphertextA, ciphertextAlpha, &mutexSwitch, txparams[2], Id, num, P)
			AlphaBshare := params.PAngle2(ciphertextB, ciphertextAlpha, &mutexSwitch, txparams[3], Id, num, P)
			fmt.Println("player", Id+1, "share A*alpha:", AlphaAshare)
			fmt.Println("player", Id+1, "share B*alpha:", AlphaBshare)
			// step 6
			ciphertextCold := publicparams.bfvMult(ciphertextA, ciphertextB)
			// step 7
			Cshare, ciphertextCnew := params.Reshare2(&mutexSwitch, txparams[4], txparams[5], ciphertextCold, Id, num, P, true)
			fmt.Println("player", Id+1, "share C:", Cshare)
			// step 8
			AlphaCshare := params.PAngle3(ciphertextCnew, ciphertextAlpha2, &mutexSwitch, txparams[6], Id, num, P)
			fmt.Println("player", Id+1, "share C*alpha:", AlphaCshare)
			//fmt.Sprint(AlphaAshare, AlphaBshare, Cshare, AlphaCshare)
			wgmain.Done()
		}(spdzparams, i, skChan)
	}
	fmt.Println("primeb:", rnsparams.primeb)
	wgmain.Wait()
	now2 := time.Now()
	time2 := now2.Sub(now1)
	close(skChan)
	return time2.Seconds()
}

func (params *spdz2Params) PAngle2(ciphertextV, ciphertextalpha *bfv.Ciphertext, mutex *sync.Mutex, txparams TxParams, Id int, num int, P []*party) (AlphaMshare []*big.Int) {
	// step 1
	ciphertextVAlpha := params.publicparams.bfvMult(ciphertextV, ciphertextalpha)
	// step 2
	AlphaMshare, _ = params.Reshare2(mutex, txparams, TxParams{}, ciphertextVAlpha, Id, num, P, false)
	return
}

func (params *spdz2Params) Reshare2(mutex *sync.Mutex, txparamsf, txparamsM TxParams, ciphertextM *bfv.Ciphertext, Id int, num int, P []*party, NewCiphertext bool) (MshareSlice []*big.Int, ciphertextMnew *bfv.Ciphertext) {
	mutex.Lock()
	// step 1
	encodef := params.encodef()
	// step 2
	ciphertextf := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(encodef)))
	mutex.Unlock()
	// step 3/4
	ciphertextfSlice := txparamsf.encTx(num, ciphertextf)
	ciphertextF := params.AddSlice(ciphertextfSlice, mutex)
	// step 5
	ciphertextCShareold := params.publicparams.bfvAdd(ciphertextM, ciphertextF)
	// step 6
	mutex.Lock()

	if Id == 0 {
		ciphertextCshare := params.publicparams.keyswitch(params.publicparams.bfvSub(ciphertextCShareold, ciphertextf), P)
		Mshare := params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextCshare)))
		MshareSlice = params.decodeValue(Mshare)
	} else {
		Mshare := encodef
		MshareSlice = params.decodeValue(Mshare)
	}
	mutex.Unlock()
	// step 7
	if NewCiphertext {
		cencodenew := Encode1(MshareSlice, params.fprime.BitLen()*2)
		mutex.Lock()
		ciphertextmnew := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(cencodenew)))
		mutex.Unlock()
		ciphertextMnewSlice := txparamsM.encTx(num, ciphertextmnew)
		ciphertextMnew = params.AddSlice(ciphertextMnewSlice, mutex)
	}
	return
}

func (params *spdz2Params) PAngle3(ciphertextV, ciphertextalpha *bfv.Ciphertext, mutex *sync.Mutex, txparams TxParams, Id int, num int, P []*party) (AlphaMshare []*big.Int) {
	// step 1
	ciphertextVAlpha := params.publicparams.bfvMult(ciphertextV, ciphertextalpha)
	// step 2
	AlphaMshare, _ = params.Reshare3(mutex, txparams, TxParams{}, ciphertextVAlpha, Id, num, P, false)
	return
}

func (params *spdz2Params) Reshare3(mutex *sync.Mutex, txparamsf, txparamsM TxParams, ciphertextM *bfv.Ciphertext, Id int, num int, P []*party, NewCiphertext bool) (MshareSlice []*big.Int, ciphertextMnew *bfv.Ciphertext) {
	mutex.Lock()
	// step 1
	encodef := params.encodef()
	// step 2
	ciphertextf := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(encodef)))
	mutex.Unlock()
	// step 3/4
	ciphertextfSlice := txparamsf.encTx(num, ciphertextf)
	ciphertextF := params.AddSlice(ciphertextfSlice, mutex)
	// step 5
	ciphertextCShareold := params.publicparams.bfvAdd(ciphertextM, ciphertextF)
	// step 6
	mutex.Lock()

	if Id == 0 {
		ciphertextCshare := params.publicparams.keyswitch(params.publicparams.bfvSub(ciphertextCShareold, ciphertextf), P)
		Mshare := params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextCshare)))
		MshareSlice = params.decodeValue2(Mshare)
	} else {
		Mshare := encodef
		MshareSlice = params.decodeValue(Mshare)
	}
	mutex.Unlock()
	// todo bit --- 128
	cencodenew := Encode1(MshareSlice, params.fprime.BitLen()*2)
	// step 7
	if NewCiphertext {
		mutex.Lock()
		ciphertextmnew := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(cencodenew)))
		mutex.Unlock()
		ciphertextMnewSlice := txparamsM.encTx(num, ciphertextmnew)
		ciphertextMnew = params.AddSlice(ciphertextMnewSlice, mutex)
	}
	return
}

func (params *spdz2Params) encodeAlpha() (encodealpha *big.Int) {
	alphaSlice := make([]*big.Int, 0)
	for i := 0; i < params.encodenum; i++ {
		alpha, _ := rand.Int(rand.Reader, params.fprime)
		alphaSlice = append(alphaSlice, alpha)
	}
	encodealpha = Encode1(alphaSlice, params.fprime.BitLen())
	return
}

func (params *spdz2Params) encodeAlpha2() (encodealpha2 *big.Int) {
	fprimealpha, _ := rand.Prime(rand.Reader, params.fprime.BitLen()*2)
	alphaSlice := make([]*big.Int, 0)
	for i := 0; i < params.encodenum; i++ {
		alpha, _ := rand.Int(rand.Reader, fprimealpha)
		alphaSlice = append(alphaSlice, alpha)
	}
	encodealpha2 = Encode1(alphaSlice, params.fprime.BitLen()*2)
	return
}

func (params *spdz2Params) encodeTripleab() (encodea, encodeb *big.Int) {
	aSlice := make([]*big.Int, 0)
	bSlice := make([]*big.Int, 0)
	for i := 0; i < params.encodenum; i++ {
		a, _ := rand.Int(rand.Reader, params.fprime)
		b, _ := rand.Int(rand.Reader, params.fprime)
		aSlice = append(aSlice, a)
		bSlice = append(bSlice, b)
	}
	encodea = Encode1(aSlice, params.fprime.BitLen())
	encodeb = Encode1(bSlice, params.fprime.BitLen())
	return
}

func (params *spdz2Params) encodef() (encodef *big.Int) {
	fSlice := make([]*big.Int, 0)
	//d := params.fprime.BitLen() + int(math.Log2(float64(params.encodenum))) + 1
	//k := d + params.fprime.BitLen()
	//fprimemask, _ := rand.Prime(rand.Reader, k)
	for i := 0; i < params.encodenum; i++ {
		f, _ := rand.Int(rand.Reader, params.fprime)
		fSlice = append(fSlice, f)
	}
	encodef = Encode2(fSlice, params.fprime.BitLen())
	return
}

func (params *spdz2Params) decodeValue(encodevalue *big.Int) (valueSlice []*big.Int) {
	valueSlice = Decode2Mult(encodevalue, params.encodenum, params.fprime.BitLen())
	return
}

func (params *spdz2Params) decodeValue2(encodevalue *big.Int) (valueSlice []*big.Int) {
	valueSlice = Decode2Mult(encodevalue, params.encodenum, params.fprime.BitLen()*2)
	return
}
