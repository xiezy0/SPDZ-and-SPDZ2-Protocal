package spdz2

import (
	"math"
	"math/big"
)

func Encode1(valueSlice []*big.Int, m int) (encodeValue *big.Int) {
	num := len(valueSlice)
	encodeValue = new(big.Int).SetUint64(0)
	for i, value := range valueSlice {
		// 2^(i-1) - 1
		exp2i_1_1 := new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(int64(i)), nil)
		exp2i_1_1.Add(exp2i_1_1, new(big.Int).Neg(new(big.Int).SetInt64(1)))
		// exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i)) - 1))
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		// value * 2 ^ (k * (2^(i-1) - 1))
		encodevalue := new(big.Int).Mul(encodebase, value)
		encodeValue.Add(encodeValue, encodevalue)
	}
	return
}

func Decode1(encodeValue *big.Int, num, m int) (valueSlice []*big.Int) {
	valueSlice = make([]*big.Int, 0)
	for i := num; i > 0; i-- {
		// 2^(i-1) - 1
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i-1)) - 1))
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		value := new(big.Int).Div(encodeValue, encodebase)
		encodeValue.Mod(encodeValue, encodebase)
		valueSlice = append(valueSlice, value)
	}
	valueSlice = rev(valueSlice)
	return
}

func Encode2(valueSlice []*big.Int, m int) (encodeValue *big.Int) {
	num := len(valueSlice)
	encodeValue = new(big.Int).SetUint64(0)
	for i, value := range valueSlice {
		// 2 *（2^(i-1) - 1）
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i))-1) * 2)
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// 2 * k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (2 * k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		// value * 2 ^ (2 * k * (2^(i-1) - 1))
		encodevalue := new(big.Int).Mul(encodebase, value)
		encodeValue.Add(encodeValue, encodevalue)
	}
	return
}

func Decode2Mult(encodeValue *big.Int, num, m int) (valueSlice []*big.Int) {
	valueSlice = make([]*big.Int, 0)
	encodebaseSlice := make([]*big.Int, 0)
	for i := num; i > 0; i-- {
		// 2^(i-1) - 1
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i-1)) - 1))
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		encodebaseSlice = append(encodebaseSlice, encodebase)
	}
	encodebaseMap := ploymultsame(encodebaseSlice, encodebaseSlice)
	encodebaseSlice = ploymult(encodebaseSlice, encodebaseSlice)
	//index := 1
	for _, encodebase := range encodebaseSlice {
		value := new(big.Int).Div(encodeValue, encodebase)
		encodeValue.Mod(encodeValue, encodebase)
		if encodebaseMap[encodebase.String()] {
			valueSlice = append(valueSlice, value)
		}
	}
	valueSlice = rev(valueSlice)
	return
}

func Decode2(encodeValue *big.Int, num, m int) (valueSlice []*big.Int) {
	valueSlice = make([]*big.Int, 0)
	for i := num; i > 0; i-- {
		// 2 *（2^(i-1) - 1）
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i-1))-1) * 2)
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// 2 * k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (2 * k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		value := new(big.Int).Div(encodeValue, encodebase)
		encodeValue.Mod(encodeValue, encodebase)
		valueSlice = append(valueSlice, value)
	}
	valueSlice = rev(valueSlice)
	return
}

func rev(slice []*big.Int) []*big.Int {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}

func ploymultsame(ploy0, ploy1 []*big.Int) map[string]bool {
	ploymultmap := make(map[*big.Int]bool)
	ploy1lengh := len(ploy1)
	for i, ploy0value := range ploy0 {
		for j := i; j < ploy1lengh; j++ {
			if j == i {
				ploymultmap[new(big.Int).Mul(ploy0value, ploy1[j])] = true
			} else {
				ploymultmap[new(big.Int).Mul(ploy0value, ploy1[j])] = false
			}
		}
	}
	return exMap(ploymultmap)
}

func ploymult(ploy0, ploy1 []*big.Int) (ploymult []*big.Int) {
	ploymult = make([]*big.Int, 0)
	ploy1lengh := len(ploy1)
	for i, ploy0value := range ploy0 {
		for j := i; j < ploy1lengh; j++ {
			ploymult = append(ploymult, (new(big.Int).Mul(ploy0value, ploy1[j])))
		}
	}
	return bubbleSortSlice(ploymult)
}

func bubbleSortSlice(arr []*big.Int) (sortSlice []*big.Int) {
	length := len(arr)
	for i := length - 1; i > 0; i-- {
		for j := length - 1; j > length-1-i; j-- {
			if arr[j].Cmp(arr[j-1]) == 1 {
				temp := arr[j]
				arr[j] = arr[j-1]
				arr[j-1] = temp
			}
		}
	}
	return arr
}

func exMap(bigMap map[*big.Int]bool) map[string]bool {
	sortMap := make(map[string]bool)
	for key, value := range bigMap {
		sortMap[key.String()] = value
	}
	return sortMap
}
