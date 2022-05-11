package spdz2

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"
)

type evaC struct {
}

func TestSpdz(t *testing.T) {
	t.Run("1goroutine", func(t *testing.T) {
		genTriple(2)
	})
	t.Run("1goroutinespdz", func(t *testing.T) {
		params, fprime, _ := spdzInit(8, 128)
		trilpA, _ := rand.Int(rand.Reader, fprime)
		trilpB, _ := rand.Int(rand.Reader, fprime)
		tripleCright := new(big.Int).Mul(trilpA, trilpB)
		tripleAaBright := new(big.Int).Add(trilpA, trilpB)
		fmt.Println("trilpA", trilpA)
		fmt.Println("trilpB", trilpB)

		publicparams, P := dkeyGen(2)
		ciphertext0 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(trilpA)))
		ciphertext1 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(trilpB)))
		ciphertext2 := publicparams.bfvAdd(ciphertext0, ciphertext1)
		ciphertext3 := publicparams.bfvMult(ciphertext0, ciphertext1)
		ciphertext2New := publicparams.keyswitch(ciphertext2, P)
		ciphertext3New := publicparams.keyswitch(ciphertext3, P)
		plaintext2 := publicparams.bfvDDec(ciphertext2New)
		plaintext3 := publicparams.bfvDDec(ciphertext3New)

		res0 := params.crt(decodeUintBigSlice(plaintext2))
		res1 := params.crt(decodeUintBigSlice(plaintext3))

		fmt.Println("trilpCright", tripleCright)
		fmt.Println("trilpCevalu", res1)
		fmt.Println("tripleAaBright", tripleAaBright)
		fmt.Println("tripleAaBevalu", res0)
	})
	t.Run("numgoroutine", func(t *testing.T) {
		GenTriple(5, 64)
	})
	t.Run("numgoroutinechann", func(t *testing.T) {
		skChan := make(chan *party, 3)
		rnsparams, fprime, wgmain := spdzInit(3, 32)
		publicparams, P := dkeyGen(3)
		mutex := sync.Mutex{}
		for i := 0; i < 3; i++ {
			go func(Id int) {
				trilpa, _ := rand.Int(rand.Reader, fprime)
				fmt.Println("goroutine:", Id)
				mutex.Lock()
				ciphertexta := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(trilpa)))
				fmt.Println("goroutine:", Id, "down")

				ciphertextAnew := publicparams.keyswitch(ciphertexta, P)
				mutex.Unlock()
				plaintext1 := publicparams.bfvDDec(ciphertextAnew)
				ppp0 := rnsparams.crt(decodeUintBigSlice(plaintext1))
				fmt.Println("goroutine", Id, "right", trilpa)
				fmt.Println("goroutine", Id, "eval", ppp0)
				wgmain.Done()
			}(i)
		}
		wgmain.Wait()
		close(skChan)
	})
}

func eva(publicparams PublicParams, rnsparams rnsParams, trilpa *big.Int, P []*party) (ppp0 *big.Int) {
	ciphertexta := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(trilpa)))
	ciphertextAnew := publicparams.keyswitch(ciphertexta, P)
	plaintext1 := publicparams.bfvDDec(ciphertextAnew)
	ppp0 = rnsparams.crt(decodeUintBigSlice(plaintext1))
	return
}
