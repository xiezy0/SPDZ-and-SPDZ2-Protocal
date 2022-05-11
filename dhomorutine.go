package spdz2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/dbfv"
	"github.com/ldsec/lattigo/v2/drlwe"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"sync"
)

func dkeyGenNew(num int) (publicParams PublicParams, P [][]party) {
	N := num
	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	paramsDef := bfv.PN15QP827pq
	paramsDef.T = 576460752260694017 // TODO: 素数生成改为随机生成
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}
	crs, err := utils.NewKeyedPRNG([]byte{'s', 'p', 'd', 'z'})
	if err != nil {
		panic(err)
	}
	encoder := bfv.NewEncoder(params)
	// 全局最后加解密的公私钥
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
	pk := new(rlwe.PublicKey)
	rlk := new(rlwe.RelinearizationKey)
	P = make([][]party, 0)

	// Create each party, and allocate the memory for all the shares that the protocols will need
	for i := 0; i < num; i++ {
		// 给每个计算方创建一个私钥
		Pi := make([]party, 0)
		Pi = genpartiesru(params, N)
		// 全局公钥创建 并共享公钥

		//pk = ckgphaseru(params, crs, Pi)
		// 全局重线性化密钥创建
		rlk = rkgphaseru(params, crs, Pi)
		P = append(P, Pi)
	}
	fmt.Println(P)
	publicParams = PublicParams{params, encoder, tsk, tpk, pk, rlk}
	return
}

// TODO: 开多个协程改写
// 创建自己的私钥
func genpartiesru(params bfv.Parameters, N int) []party {
	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]party, N)
	for i := range P {
		pi := party{}
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()
		P[i] = pi
	}
	return P
}

// 单个计算方加密元素
func (params *PublicParams) bfvEncru(input []uint64) (Ciphertext *bfv.Ciphertext) {
	Ciphertext = bfv.NewCiphertext(params.params, 1)
	encryptor := bfv.NewEncryptor(params.params, params.pk)
	plaintext := bfv.NewPlaintext(params.params)
	params.encoder.EncodeUint(input, plaintext)
	encryptor.Encrypt(plaintext, Ciphertext)
	return
}

// 同态加法
func (params *PublicParams) bfvAddru(Ciphertext0 *bfv.Ciphertext, Ciphertext1 *bfv.Ciphertext) (CiphertextAdd *bfv.Ciphertext) {
	evaluator := bfv.NewEvaluator(params.params, rlwe.EvaluationKey{Rlk: params.rlk})
	CiphertextAdd = evaluator.AddNew(Ciphertext0, Ciphertext1)
	evaluator.Relinearize(CiphertextAdd, CiphertextAdd)
	return
}

// 同态乘法
func (params *PublicParams) bfvMultru(Ciphertext0 *bfv.Ciphertext, Ciphertext1 *bfv.Ciphertext) (CiphertextMult *bfv.Ciphertext) {
	evaluator := bfv.NewEvaluator(params.params, rlwe.EvaluationKey{Rlk: params.rlk})
	CiphertextMult = evaluator.MulNew(Ciphertext0, Ciphertext1)
	evaluator.Relinearize(CiphertextMult, CiphertextMult)
	return
}

func (params *PublicParams) eval1Phaseru(NGoRoutine int, encInputs []*bfv.Ciphertext) (encRes *bfv.Ciphertext) {

	encLvls := make([][]*bfv.Ciphertext, 0)
	encLvls = append(encLvls, encInputs)
	for nLvl := len(encInputs) / 2; nLvl > 0; nLvl = nLvl >> 1 {
		encLvl := make([]*bfv.Ciphertext, nLvl)
		for i := range encLvl {
			encLvl[i] = bfv.NewCiphertext(params.params, 2)
		}
		encLvls = append(encLvls, encLvl)
	}
	encRes = encLvls[len(encLvls)-1][0]

	evaluator := bfv.NewEvaluator(params.params, rlwe.EvaluationKey{Rlk: params.rlk, Rtks: nil})
	// Split the task among the Go routines
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)
	//l.Println("> Spawning", NGoRoutine, "evaluator goroutine")
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // creates a shallow evaluator copy for this goroutine
			for task := range tasks {
				// 1) Multiplication of two input vectors
				evaluator.Add(task.op1, task.op2, task.res)
				// 2) Relinearization
				evaluator.Relinearize(task.res, task.res)
				task.wg.Done()
			}
			//l.Println("\t evaluator", i, "down")
			workers.Done()
		}(i)
		//l.Println("\t evaluator", i, "started")
	}

	// Start the tasks
	for i, lvl := range encLvls[:len(encLvls)-1] {
		nextLvl := encLvls[i+1]
		wg := &sync.WaitGroup{}
		wg.Add(len(nextLvl))
		// 每两对并行处理密文
		for j, nextLvlCt := range nextLvl {
			task := multTask{wg, lvl[2*j], lvl[2*j+1], nextLvlCt, 0}
			tasks <- &task
		}
		wg.Wait()
	}
	//l.Println("> Shutting down workers")
	close(tasks)
	workers.Wait()

	return
}

// TODO: 开多个协程改写
func (params *PublicParams) bfvDDecru(Ciphertext *bfv.Ciphertext) (output []uint64) {
	decryptor := bfv.NewDecryptor(params.params, params.tsk)
	ptres := bfv.NewPlaintext(params.params)
	decryptor.Decrypt(Ciphertext, ptres)
	output = params.encoder.DecodeUintNew(ptres)
	return
}

// TODO: 开多个协程改写
func (params *PublicParams) keyswitchru(ciphertextOld *bfv.Ciphertext, P []party) (ciphertextNew *bfv.Ciphertext) {
	// Collective key switching from the collective secret key to
	// the target public key
	pcks := dbfv.NewPCKSProtocol(params.params, 3.19)
	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShareBFV()
	}

	for _, pi := range P {
		pcks.GenShare(pi.sk, params.tpk, ciphertextOld.Ciphertext, pi.pcksShare)
	}
	pcksCombined := pcks.AllocateShareBFV()
	ciphertextNew = bfv.NewCiphertext(params.params, 1)
	for _, pi := range P {
		pcks.AggregateShares(pi.pcksShare, pcksCombined, pcksCombined)
	}
	pcks.KeySwitch(pcksCombined, ciphertextOld.Ciphertext, ciphertextNew.Ciphertext)
	return
}

func ckgphaseru(params bfv.Parameters, crs utils.PRNG, P []party) (pk *rlwe.PublicKey, Pnew []party) {
	Pnew = P
	ckg := dbfv.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShares()
	for _, pi := range Pnew {
		pi.ckgShare = ckg.AllocateShares()
	}
	// 创建publickey的共享  p_i.sk * crp + e_i
	crp := ckg.SampleCRP(crs)
	for _, pi := range Pnew {
		sk := new(rlwe.SecretKey)
		ckgshare := new(drlwe.CKGShare)
		ckg.GenShare(sk, crp, ckgshare)
		pi.sk = sk
	}

	// 创建公钥b 将多方公钥的共享相加
	pk = bfv.NewPublicKey(params)
	for _, pi := range P {
		ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
	}
	// 格式化公钥 a, b
	ckg.GenPublicKey(ckgCombined, crp, pk)

	return
}

func rkgphaseru(params bfv.Parameters, crs utils.PRNG, P []party) *rlwe.RelinearizationKey {

	rkg := dbfv.NewRKGProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShares()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShares()
	}
	crp := rkg.SampleCRP(crs)

	for _, pi := range P {
		rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
	}
	for _, pi := range P {
		rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, rkgCombined1)
	}
	for _, pi := range P {
		rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
	}
	rlk := bfv.NewRelinearizationKey(params, 1)
	for _, pi := range P {
		rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
	}
	rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)

	return rlk
}
