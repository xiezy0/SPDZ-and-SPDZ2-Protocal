package spdz2

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"sync"
	"sync/atomic"
)

type Transaction interface {
	encTx(players int, enc *bfv.Ciphertext) (m []*bfv.Ciphertext)
}

type TxParams struct {
	mutex    *sync.Mutex
	ch       chan *bfv.Ciphertext
	queuelen uint64
}

func encTxInitMul(players int, gennum int) (txparams []TxParams) {
	txparams = make([]TxParams, 0)
	for i := 0; i < gennum; i++ {
		txparams = append(txparams, encTxInit(players))
	}
	return
}

func encTxInit(players int) (txparams TxParams) {
	mutex := sync.Mutex{}
	ch := make(chan *bfv.Ciphertext, players)
	queuelen := uint64(0)
	txparams = TxParams{&mutex, ch, queuelen}
	return
}

func (txparams TxParams) encTx(players int, enc *bfv.Ciphertext) (m []*bfv.Ciphertext) {
	mutex := txparams.mutex
	ch := txparams.ch
	queuelen := txparams.queuelen
	m = make([]*bfv.Ciphertext, players)
	ch <- enc
LABEL:
	mutex.Lock()
	if atomic.StoreUint64(&queuelen, uint64(len(ch))); atomic.CompareAndSwapUint64(&queuelen, uint64(players), 0) {
		for j := 0; j < players; j++ {
			m[j] = <-ch
		}
		for j := 0; j < players; j++ {
			ch <- m[j]
		}
		mutex.Unlock()
	} else {
		mutex.Unlock()
		goto LABEL
	}
	return
}
