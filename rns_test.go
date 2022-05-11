package spdz2

import (
	"fmt"
	"math/big"
	"testing"
)

func TestRnsgen(t *testing.T) {
	n0, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	n1, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	fmt.Println("n0:::::::", n0)
	fmt.Println("n1:::::::", n1)
	params := rnsInit(2, []*big.Int{n0, n1})
	rnscom, _ := params.rns(n0)
	fmt.Println("commeva::", rnscom)
	rnsadd := params.rnsAddTest(n0, n1)
	fmt.Println("addeva:::", rnsadd)
	rnsmult := params.rnsMultTest(n0, n1)
	fmt.Println("multeva::", rnsmult)
}
