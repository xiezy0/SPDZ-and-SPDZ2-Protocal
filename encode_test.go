package spdz2

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestEncode(t *testing.T) {
	t.Run("testEncode1", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 64)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceAddRight := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceAddRight = append(valueSliceAddRight, new(big.Int).Add(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value0Slice:", value1Slice)
		encodevalue0 := Encode1(value0Slice, 64)
		encodevalue1 := Encode1(value1Slice, 64)
		decodeaddSlice := Decode1(new(big.Int).Add(encodevalue0, encodevalue1), 8, 64)
		fmt.Println("addright:", valueSliceAddRight)
		fmt.Println("addevalu:", decodeaddSlice)
	})
	t.Run("testEncode2", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 64)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceAddRight := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceAddRight = append(valueSliceAddRight, new(big.Int).Add(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value0Slice:", value1Slice)
		encodevalue0 := Encode2(value0Slice, 64)
		encodevalue1 := Encode2(value1Slice, 64)
		decodeaddSlice := Decode2(new(big.Int).Add(encodevalue0, encodevalue1), 8, 64)
		fmt.Println("addright:", valueSliceAddRight)
		fmt.Println("addevalu:", decodeaddSlice)
	})
	t.Run("testEncode12", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 64)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceMultRight := make([]*big.Int, 0)
		for i := 0; i < 16; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceMultRight = append(valueSliceMultRight, new(big.Int).Mul(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value1Slice:", value1Slice)

		encodevalue0 := Encode1(value0Slice, 64)
		encodevalue1 := Encode1(value1Slice, 64)
		fmt.Println(encodevalue0, encodevalue1)
		decodemultSlice := Decode2Mult(new(big.Int).Mul(encodevalue0, encodevalue1), 16, 64)
		fmt.Println("multright:", valueSliceMultRight)
		fmt.Println("multevalu:", decodemultSlice)
	})
	t.Run("testMask", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 64)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceMultRight := make([]*big.Int, 0)
		maskSlice := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			valuemask, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			maskSlice = append(maskSlice, valuemask)
			value012 := new(big.Int).Mul(value0, value1)
			value012.Add(value012, valuemask)
			valueSliceMultRight = append(valueSliceMultRight, value012)
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value1Slice:", value1Slice)
		fmt.Println("maskSlice", maskSlice)

		encodevalue0 := Encode1(value0Slice, 64)
		encodevalue1 := Encode1(value1Slice, 64)
		encodemask := Encode2(maskSlice, 64)
		encodemul := new(big.Int).Mul(encodevalue0, encodevalue1)
		encodemul.Add(encodemul, encodemask)
		decodemultSlice := Decode2Mult(encodemul, 8, 64)
		fmt.Println("multright:", valueSliceMultRight)
		fmt.Println("multevalu:", decodemultSlice)
	})
	t.Run("testploy", func(t *testing.T) {
		ploy0 := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3)}
		ploy1 := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3)}
		ployres := ploymult(ploy0, ploy1)
		fmt.Println(ployres)
	})
	t.Run("testploysame", func(t *testing.T) {
		ploy0 := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(6)}
		ploy1 := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(6)}
		ployres := ploymultsame(ploy0, ploy1)
		fmt.Println(ployres)
	})
	t.Run("Testhomoploy", func(t *testing.T) {
		params, fprime, _ := spdz2Init(2, 64)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceMultRight := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, fprime)
			value1, _ := rand.Int(rand.Reader, fprime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceMultRight = append(valueSliceMultRight, new(big.Int).Mul(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value1Slice:", value1Slice)

		encodevalue0 := Encode1(value0Slice, 64)
		encodevalue1 := Encode1(value1Slice, 64)

		fmt.Println(new(big.Int).Mul(encodevalue0, encodevalue1))
		publicparams, P := dkeyGen(2)
		ciphertext0 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(encodevalue0)))
		ciphertext1 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(encodevalue1)))
		ciphertext3 := publicparams.bfvMult(ciphertext0, ciphertext1)
		ciphertext3New := publicparams.keyswitch(ciphertext3, P)
		plaintext3 := publicparams.bfvDDec(ciphertext3New)
		res1 := params.crt(decodeUintBigSlice(plaintext3))
		fmt.Println(res1)

		decodemultSlice := Decode2Mult(res1, 8, 64)
		fmt.Println("multright:", valueSliceMultRight)
		fmt.Println("multevalu:", decodemultSlice)
	})
	t.Run("Testhomoask", func(t *testing.T) {
		params, fprime, _ := spdz2Init(2, 64)
		fprimemask, _ := rand.Prime(rand.Reader, 132)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceMultRight := make([]*big.Int, 0)
		maskSlice := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, fprime)
			value1, _ := rand.Int(rand.Reader, fprime)
			valuemask, _ := rand.Int(rand.Reader, fprimemask)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			maskSlice = append(maskSlice, valuemask)
			value012 := new(big.Int).Mul(value0, value1)
			value012.Add(value012, valuemask)
			valueSliceMultRight = append(valueSliceMultRight, value012)
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value1Slice:", value1Slice)
		fmt.Println("maskSlice", maskSlice)

		encodevalue0 := Encode1(value0Slice, 64)
		encodevalue1 := Encode1(value1Slice, 64)
		encodemask := Encode2(maskSlice, 64)

		publicparams, P := dkeyGen(2)
		ciphertext0 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(encodevalue0)))
		ciphertext1 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(encodevalue1)))
		ciphertextmask := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(encodemask)))

		ciphertext3 := publicparams.bfvMult(ciphertext0, ciphertext1)
		ciphertext4 := publicparams.bfvAdd(ciphertext3, ciphertextmask)

		ciphertext3New := publicparams.keyswitch(ciphertext4, P)
		plaintext3 := publicparams.bfvDDec(ciphertext3New)
		res1 := params.crt(decodeUintBigSlice(plaintext3))
		fmt.Println(res1)

		decodemultSlice := Decode2Mult(res1, 8, 64)
		fmt.Println("multright:", valueSliceMultRight)
		fmt.Println("multevalu:", decodemultSlice)
	})

}
