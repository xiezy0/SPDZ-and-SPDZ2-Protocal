package spdz2

import (
	"fmt"
	"testing"
)

func TestDhomo(t *testing.T) {
	t.Run("2player", func(t *testing.T) {
		publicparams, P := dkeyGen(2)
		ciphertext0 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext1 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext2 := publicparams.bfvAdd(ciphertext0, ciphertext1)
		ciphertext2 = publicparams.bfvSub(ciphertext2, ciphertext1)
		ciphertext3 := publicparams.bfvMult(ciphertext0, ciphertext1)
		ciphertext2New := publicparams.keyswitch(ciphertext2, P)
		ciphertext3New := publicparams.keyswitch(ciphertext3, P)
		plaintext2 := publicparams.bfvDDec(ciphertext2New)
		plaintext3 := publicparams.bfvDDec(ciphertext3New)
		fmt.Println(plaintext2)
		fmt.Println(plaintext3)
	})
	t.Run("4player", func(t *testing.T) {
		publicparams, P := dkeyGen(4)
		ciphertext0 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext1 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext2 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext3 := publicparams.bfvEnc([]uint64{2, 4, 6})

		ciphertext0123add := publicparams.bfvAdd(ciphertext0, ciphertext1)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext2)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext3)

		ciphertext0123mult := publicparams.bfvMult(ciphertext0, ciphertext1)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext2)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext3)

		ciphertext0123addNew := publicparams.keyswitch(ciphertext0123add, P)
		ciphertext0123multNew := publicparams.keyswitch(ciphertext0123mult, P)

		plaintext2 := publicparams.bfvDDec(ciphertext0123addNew)
		plaintext3 := publicparams.bfvDDec(ciphertext0123multNew)

		fmt.Println(plaintext2)
		fmt.Println(plaintext3)
	})
	t.Run("8player", func(t *testing.T) {
		publicparams, P := dkeyGen(8)
		ciphertext0 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext1 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext2 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext3 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext4 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext5 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext6 := publicparams.bfvEnc([]uint64{2, 4, 6})
		ciphertext7 := publicparams.bfvEnc([]uint64{2, 4, 6})

		ciphertext0123add := publicparams.bfvAdd(ciphertext0, ciphertext1)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext2)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext3)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext4)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext5)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext6)
		ciphertext0123add = publicparams.bfvAdd(ciphertext0123add, ciphertext7)

		ciphertext0123mult := publicparams.bfvMult(ciphertext0, ciphertext1)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext2)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext3)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext4)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext5)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext6)
		ciphertext0123mult = publicparams.bfvMult(ciphertext0123mult, ciphertext7)

		ciphertext0123addNew := publicparams.keyswitch(ciphertext0123add, P)
		ciphertext0123multNew := publicparams.keyswitch(ciphertext0123mult, P)

		plaintext2 := publicparams.bfvDDec(ciphertext0123addNew)
		plaintext3 := publicparams.bfvDDec(ciphertext0123multNew)

		fmt.Println(plaintext2)
		fmt.Println(plaintext3)
	})

}
