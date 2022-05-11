package spdz2

import (
	"crypto/rand"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"math/big"
	"strconv"
	"sync"
	"time"
)

type SpdzHigh interface {
	PAngle(ciphertextV, ciphertextalpha *bfv.Ciphertext, mutex *sync.Mutex, txparams TxParams, Id int, num int, P []*party) (AlphaMshare *big.Int)
	Reshare(mutex *sync.Mutex, txparamsf, txparamsM TxParams, ciphertextM *bfv.Ciphertext, Id int, num int, P []*party, NewCiphertext bool) (Mshare *big.Int, ciphertextMnew *bfv.Ciphertext)
}

type SpdzLow interface {
	SpdzHigh
	AddSlice(ciphertextSlice []*bfv.Ciphertext, mutex *sync.Mutex) (ciphertextAdd *bfv.Ciphertext)
	MultSlice(ciphertextSlice []*bfv.Ciphertext, mutex *sync.Mutex) (ciphertextMult *bfv.Ciphertext)
}

// the public params of SPDZ
type spdzParams struct {
	rnsparams    rnsParams
	publicparams PublicParams
	fprime       *big.Int
}

func spdzInit(num int, security int) (params rnsParams, fprime *big.Int, wgmain sync.WaitGroup) {
	params = rnspdzInit(num, security)
	fprime, _ = rand.Prime(rand.Reader, security)
	wgmain = sync.WaitGroup{}
	wgmain.Add(num)
	return
}

func GenTriple(num int, security int) {
	skChan := make(chan *party, num)
	rnsparams, fprime, wgmain := spdzInit(num, security)
	publicparams, P := dkeyGen(num)
	spdzparams := spdzParams{rnsparams, publicparams, fprime}
	txparams := encTxInitMul(num, 7)
	trilpAlpha, _ := rand.Int(rand.Reader, fprime)
	ciphertextAlpha := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(trilpAlpha)))
	fmt.Println("alpha", trilpAlpha)
	mutexSwitch := sync.Mutex{}
	for i := 0; i < num; i++ {
		skChan <- P[i]
	}
	// num goroutine <---> num players
	now1 := time.Now()
	for i := 0; i < num; i++ {
		go func(params spdzParams, Id int, convSyncChan0 <-chan *party) {
			// step 1
			trilpa, _ := rand.Int(rand.Reader, params.fprime)
			trilpb, _ := rand.Int(rand.Reader, params.fprime)
			//psk := <-convSyncChan0
			//fmt.Println(psk)
			// step 2
			mutexSwitch.Lock()
			ciphertexta := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpa)))
			ciphertextb := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpb)))
			mutexSwitch.Unlock()
			//txparams0 := TxParams{&mutex0, encch0, queuelen0}
			//txparams1 := TxParams{&mutex1, encch1, queuelen1}
			ciphertextaSlice := txparams[0].encTx(num, ciphertexta)
			ciphertextbSlice := txparams[1].encTx(num, ciphertextb)
			// step 3&4
			ciphertextA := params.AddSlice(ciphertextaSlice, &mutexSwitch)
			ciphertextB := params.AddSlice(ciphertextbSlice, &mutexSwitch)
			// step 5
			AlphaAshare := params.PAngle(ciphertextA, ciphertextAlpha, &mutexSwitch, txparams[2], Id, num, P)
			AlphaBshare := params.PAngle(ciphertextB, ciphertextAlpha, &mutexSwitch, txparams[3], Id, num, P)
			fmt.Println("player", Id+1, "share A*Δ:", AlphaAshare)
			fmt.Println("player", Id+1, "share B*Δ:", AlphaBshare)
			// step 6
			ciphertextCold := publicparams.bfvMult(ciphertextA, ciphertextB)
			// step 7
			Cshare, ciphertextCnew := params.Reshare(&mutexSwitch, txparams[4], txparams[5], ciphertextCold, Id, num, P, true)
			fmt.Println("player", Id+1, "share C:", Cshare)
			// step 8
			AlphaCshare := params.PAngle(ciphertextCnew, ciphertextAlpha, &mutexSwitch, txparams[6], Id, num, P)
			fmt.Println("player", Id+1, "share C*Δ:", AlphaCshare)

			wgmain.Done()
		}(spdzparams, i, skChan)
	}
	// fmt.Println(rnsparams.primeb)
	wgmain.Wait()
	now2 := time.Now()
	time2 := now2.Sub(now1)
	fmt.Println("执行消耗的时间为: ", time2)
	close(skChan)
}

func (params *spdzParams) PAngle(ciphertextV, ciphertextalpha *bfv.Ciphertext, mutex *sync.Mutex, txparams TxParams, Id int, num int, P []*party) (AlphaMshare *big.Int) {
	// step 1
	ciphertextVAlpha := params.publicparams.bfvMult(ciphertextV, ciphertextalpha)
	// step 2
	AlphaMshare, _ = params.Reshare(mutex, txparams, TxParams{}, ciphertextVAlpha, Id, num, P, false)
	return
}

func (params *spdzParams) Reshare(mutex *sync.Mutex, txparamsf, txparamsM TxParams, ciphertextM *bfv.Ciphertext, Id int, num int, P []*party, NewCiphertext bool) (Mshare *big.Int, ciphertextMnew *bfv.Ciphertext) {
	mutex.Lock()
	// step 1
	f, _ := rand.Int(rand.Reader, params.fprime)
	// step 2
	ciphertextf := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(f)))
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
		Mshare = params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextCshare)))
	} else {
		Mshare = f
	}
	mutex.Unlock()
	// step 7
	if NewCiphertext {
		mutex.Lock()
		ciphertextmnew := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(Mshare)))
		mutex.Unlock()
		ciphertextMnewSlice := txparamsM.encTx(num, ciphertextmnew)
		ciphertextMnew = params.AddSlice(ciphertextMnewSlice, mutex)
	}
	return
}

func (params *spdzParams) AddSlice(ciphertextSlice []*bfv.Ciphertext, mutex *sync.Mutex) (ciphertextAdd *bfv.Ciphertext) {
	mutex.Lock()
	bigzero := new(big.Int).SetInt64(0)
	ciphertextAdd = params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(bigzero)))
	mutex.Unlock()
	for _, ciphertext := range ciphertextSlice {
		ciphertextAdd = params.publicparams.bfvAdd(ciphertextAdd, ciphertext)
	}
	return
}

func (params *spdzParams) MultSlice(ciphertextSlice []*bfv.Ciphertext, mutex *sync.Mutex) (ciphertextMult *bfv.Ciphertext) {
	mutex.Lock()
	bigzero := new(big.Int).SetInt64(1)
	ciphertextMult = params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(bigzero)))
	mutex.Unlock()
	for _, ciphertext := range ciphertextSlice {
		ciphertextMult = params.publicparams.bfvMult(ciphertextMult, ciphertext)
	}
	return
}

func encodeBigUintSlice(plaintextBigSlice []*big.Int) (plaintextUintSlice []uint64) {
	plaintextUintSlice = make([]uint64, 0)
	for _, plaintextBig := range plaintextBigSlice {
		plaintextUintSlice = append(plaintextUintSlice, encodeBigUint(plaintextBig))
	}
	return
}

func decodeUintBigSlice(plaintextUintSlice []uint64) (plaintextBigSlice []*big.Int) {
	plaintextBigSlice = make([]*big.Int, 0)
	for _, plaintextUint := range plaintextUintSlice {
		plaintextBigSlice = append(plaintextBigSlice, decodeUintBig(plaintextUint))
	}
	return
}

func encodeBigUint(plaintextBig *big.Int) (plaintextUint uint64) {
	plaintextUint, erro := strconv.ParseUint(plaintextBig.String(), 10, 64)
	if erro != nil {
		panic(erro)
	}
	return
}

func decodeUintBig(plaintextUint uint64) (plaintextBig *big.Int) {
	return new(big.Int).SetUint64(plaintextUint)
}

func genTriple(num int) {
	fprime, _ := rand.Prime(rand.Reader, 64)
	trilpA, _ := rand.Int(rand.Reader, fprime)
	trilpB, _ := rand.Int(rand.Reader, fprime)
	tripleCright := new(big.Int).Mul(trilpA, trilpB)
	tripleAaBright := new(big.Int).Add(trilpA, trilpB)
	fmt.Println("trilpA", trilpA)
	fmt.Println("trilpB", trilpB)

	params := rnsInit(num, []*big.Int{trilpA, trilpB})

	publicparams, P := dkeyGen(num)
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
}

//func GenTriple(num int) {
//	skChan := make(chan *party, num)
//	rnsparams, fprime := spdzInit(num, 64)
//	publicparams, P := dkeyGen(num)
//	spdzparams := spdzParams{rnsparams, publicparams, fprime}
//	//wgmain, _, _, _ := encTxInit(num)
//	//wgmain1, _, _, _ := encTxInit(num)
//	wgmain, mutex, encch, queuelen := encTxInit(num)
//	_, mutex1, encch1, queuelen1 := encTxInit(num)
//	_, mutex2, encch2, queuelen2 := encTxInit(num)
//	_, mutex3, encch3, queuelen3 := encTxInit(num)
//	trilpAlpha, _ := rand.Int(rand.Reader, fprime)
//	ciphertextAlpha := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(trilpAlpha)))
//	fmt.Println("alpha", trilpAlpha)
//	mutexSwitch := sync.Mutex{}
//	for i := 0; i < num; i++ {
//		skChan <- P[i]
//	}
//	//bigone  := new(big.Int).SetInt64(1)
//	//bigzero := new(big.Int).SetInt64(0)
//	// num goroutine <---> num players
//	for i := 0; i < num; i++ {
//		go func(params spdzParams, Id int, convSyncChan0 <-chan *party) {
//			trilpa, _ := rand.Int(rand.Reader, params.fprime)
//			trilpb, _ := rand.Int(rand.Reader, params.fprime)
//			f, _ := rand.Int(rand.Reader, params.fprime)
//			//psk := <-convSyncChan0
//			//fmt.Println(psk)
//			mutexSwitch.Lock()
//			ciphertexta := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpa)))
//			ciphertextb := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpb)))
//			ciphertextf := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(f)))
//			mutexSwitch.Unlock()
//			//
//			ciphertextaSlice := encTx(&mutex, encch, Id, num, queuelen, ciphertexta)
//			ciphertextbSlice := encTx(&mutex1, encch1, Id, num, queuelen1, ciphertextb)
//			ciphertextfSlice := encTx(&mutex2, encch2, Id, num, queuelen2, ciphertextf)
//
//			// fmt.Println("goroutine", Id, ":", ciphertextaSlice, ciphertextbSlice)
//			ciphertextA := params.AddSlice(ciphertextaSlice, &mutexSwitch)
//			ciphertextB := params.AddSlice(ciphertextbSlice, &mutexSwitch)
//			ciphertextF := params.AddSlice(ciphertextfSlice, &mutexSwitch)
//
//			ciphertextCold := publicparams.bfvMult(ciphertextA, ciphertextB)
//			ciphertextCShareold := publicparams.bfvAdd(ciphertextCold, ciphertextF)
//
//			mutexSwitch.Lock()
//			plaintextCshare := new(big.Int)
//			if Id == 0 {
//				ciphertextCshare := params.publicparams.keyswitch(publicparams.bfvSub(ciphertextCShareold, ciphertextf), P)
//				plaintextCshare = params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextCshare)))
//			} else {
//				plaintextCshare = f
//			}
//			mutexSwitch.Unlock()
//
//			mutexSwitch.Lock()
//			fmt.Println("player", Id, "share C:", plaintextCshare)
//			ciphertextcnew := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(plaintextCshare)))
//			mutexSwitch.Unlock()
//
//			ciphertextcSlice := encTx(&mutex3, encch3, Id, num, queuelen3, ciphertextcnew)
//
//			ciphertextCnew := params.AddSlice(ciphertextcSlice, &mutexSwitch)
//			ciphertextCnewAlpha := publicparams.bfvMult(ciphertextCnew, ciphertextAlpha)
//			ciphertextCnewAlphashare := publicparams.bfvAdd(ciphertextCnewAlpha, ciphertextF)
//
//			mutexSwitch.Lock()
//			plaintextCalphashare := new(big.Int)
//			if Id == 0 {
//				ciphertextswitch := publicparams.bfvSub(ciphertextCnewAlphashare, ciphertextf)
//				ciphertextAnew := params.publicparams.keyswitch(ciphertextswitch, P)
//				plaintextCalphashare = params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextAnew)))
//			} else {
//				plaintextCalphashare = f
//				dddddddd := params.publicparams.keyswitch(ciphertextCnewAlphashare, P)
//				tttttttt := params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(dddddddd)))
//				fmt.Println(tttttttt)
//			}
//			fmt.Println("player", Id, "share C*Δ:", plaintextCalphashare)
//			mutexSwitch.Unlock()
//
//			wgmain.Done()
//		}(spdzparams, i, skChan)
//	}
//	fmt.Println(rnsparams.primeb)
//	wgmain.Wait()
//	close(skChan)
//	//time.Sleep(time.Second * 4)  3343168732
//
//}
