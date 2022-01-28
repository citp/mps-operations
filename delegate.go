package main

import (
	"fmt"
	"math/big"
	"time"
)

// #############################################################################

func (p *Party) RunParallelDelegate(R *HashMapValues, pool *WorkerPool, fn WorkerFunc, ctx WorkerCtx) {
	res := pool.Run(fn, ctx)
	for i := 0; i < len(res); i++ {
		data, ok := res[i].data.(DHOutput)
		Assert(ok)
		R.DHData[res[i].id] = HashMapValue{data.Q, data.S}
		R.EGData[res[i].id] = data.Ct
	}
}

// #############################################################################

func (d *Delegate) Init(id, n, nBits int, dPath, lPath string, showP bool, ctx *EGContext) {
	d.party.Init(id, n, nBits, dPath, lPath, showP, ctx)
	d.alpha = d.party.ctx.ecc.RandomScalar()
	d.party.ctx.ecc.EC_BaseMultiply(d.alpha, &d.L)
}

func (d *Delegate) DelegateStart(M *HashMapValues) {
	defer Timer(time.Now(), d.party.log, "DelegateStart")

	*M = NewHashMap(d.party.nBits)
	pool := NewWorkerPool(uint64(len(d.party.X)))
	unmodified := GetBitMap(M.Size())
	ctx := BlindCtxSum{&d.party.ctx, d.alpha, d.party.agg_pk, d.party.partial_sk}
	for w, v := range d.party.X {
		idx := GetIndex(w, M.nBits)
		pool.InChan <- WorkerInput{idx, BlindInput{w, v}}
		unmodified.Remove(idx)
	}

	// var pk DHElement
	// d.party.ctx.EG_PubKey(d.party.partial_sk, &pk)
	d.party.RunParallelDelegate(M, pool, BlindWorker, ctx)
	filled := uint64(M.Size()) - unmodified.GetCardinality()
	d.party.log.Printf("filled slots=%d (expected=%f) / prop=%f\n", filled, E_FullSlots(float64(M.Size()), float64(len(d.party.X))), float64(filled)/float64(len(d.party.X)))

	pool = NewWorkerPool(unmodified.GetCardinality())
	k := unmodified.Iterator()
	for k.HasNext() {
		pool.InChan <- WorkerInput{k.Next(), RandomizeInput{}}
	}
	d.party.RunParallelDelegate(M, pool, RandomizeDelegateWorker, BlindCtxSum{&d.party.ctx, d.alpha, d.party.agg_pk, d.party.partial_sk})
}

func (d *Delegate) DelegateFinish(R *HashMapFinal) (int, EGCiphertext) {
	defer Timer(time.Now(), d.party.log, "DelegateFinish")

	sz := len(R.Q)
	pool := NewWorkerPool(uint64(sz))
	for i := 0; i < sz; i++ {
		pool.InChan <- WorkerInput{uint64(i), UnblindInput{R.Q[i], R.AES[i]}}
	}
	res := pool.Run(UnblindWorker, BlindCtxSum{&d.party.ctx, d.alpha, d.party.agg_pk, d.party.partial_sk})

	var ctSum EGCiphertext
	// var pt big.Int

	first := true
	count := 0
	for i := 0; i < len(res); i++ {
		data, _ := res[i].data.(*EGCiphertext)
		if data != nil {
			count += 1
			// d.party.ctx.EG_Decrypt(d.party.partial_sk, &pt, data)
			// fmt.Println("pt =>", pt.Text(10))
			if first {
				ctSum = *data
				first = false
			} else {
				d.party.ctx.EG_AddInplace(&ctSum, data)
			}
		}
	}
	fmt.Println("Count:", count)

	// d.party.ctx.EG_Decrypt(d.party.partial_sk, &pt, &ctSum)
	// fmt.Println("Sum:", pt.Text(10))

	// fmt.Printf("ExpectedCollidedIndices=%f", ExpectedCollidedIndices(d.nBits, d.party.n, len(d.party.X)))
	return count, ctSum
}

func (d *Delegate) JointDecryption(ctSum *EGCiphertext, partials [][]DHElement) big.Int {
	defer Timer(time.Now(), d.party.log, "JointDecryption")

	var result big.Int
	d.party.ctx.EGMP_AggDecrypt(partials, &result, ctSum)
	return result
}
