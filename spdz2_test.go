package spdz2

import (
	"fmt"
	"testing"
)

var (
	time1 float64
	time2 float64
	time3 float64
	time4 float64
	time5 float64
	time6 float64
	time7 float64
	time8 float64
	time9 float64
)

func TestSpdz2(t *testing.T) {
	t.Run("spdz2Test", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			time2 += GenTriple2(2, 40, 10)
			time3 += GenTriple2(3, 40, 10)
			time4 += GenTriple2(4, 40, 10)
			time5 += GenTriple2(5, 40, 10)
			time6 += GenTriple2(6, 40, 10)
		}
		fmt.Println("50 triples 2 players: ", 50/time2)
		fmt.Println("50 triples 3 players: ", 50/time3)
		fmt.Println("50 triples 4 players: ", 50/time4)
		fmt.Println("50 triples 5 players: ", 50/time5)
		fmt.Println("50 triples 6 players: ", 50/time6)
	})
	t.Run("spdz2Test2", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			time1 += GenTriple2(5, 40, 2)
			time2 += GenTriple2(5, 40, 4)
			time3 += GenTriple2(5, 40, 6)
			time4 += GenTriple2(5, 40, 8)
			time5 += GenTriple2(5, 40, 10)
			time6 += GenTriple2(5, 40, 12)
			time7 += GenTriple2(5, 40, 14)
			time8 += GenTriple2(5, 40, 16)
		}
		fmt.Println("6 triples 5 players: ", 6/time1)
		fmt.Println("12 triples 5 players: ", 12/time2)
		fmt.Println("18 triples 5 players: ", 18/time3)
		fmt.Println("24 triples 5 players: ", 24/time4)
		fmt.Println("30 triples 5 players: ", 30/time5)
		fmt.Println("36 triples 5 players: ", 36/time6)
		fmt.Println("42 triples 5 players: ", 42/time7)
		fmt.Println("48 triples 5 players: ", 48/time8)
	})
}
