package main

import (
	"math/big"
	"time"
)

// #############################################################################

func (p *Party) RunParallelDelegate(R *HashMapValues, pool *WorkerPool, fn WorkerFunc, ctx WorkerCtx) {
	res := pool.Run(fn, ctx)
	for i := 0; i < len(res); i++ {
		data, ok := res[i].data.(DHOutput)
		Assert(ok)
		R.DHData[res[i].id] = HashMapValue{DHElement{}, data.S}
		R.EncData[res[i].id] = data.Ct
	}
}

// #############################################################################

func (d *Delegate) Init(id, n, nBits int, dPath, lPath string, showP bool, ctx *EGContext) {
	d.party.Init(id, n, nBits, dPath, lPath, showP, ctx)
	d.alpha = d.party.ctx.ecc.RandomScalar()
	d.aesKey = RandomBytes(32)
	d.party.ctx.ecc.EC_BaseMultiply(d.alpha, &d.L)
}

func (d *Delegate) DelegateStart(M *HashMapValues, sum bool) {
	defer Timer(time.Now(), d.party.log, "DelegateStart")

	*M = NewHashMap(d.party.nBits)
	unmodified := GetBitMap(M.Size())

	var ctxSum BlindCtxSum
	var ctxInt BlindCtxInt

	if sum {
		ctxSum = BlindCtxSum{ctx: &d.party.ctx, alpha: d.alpha, pk: d.party.agg_pk, sk: d.party.partial_sk, h2c: d.party.h2c}
	} else {
		ctxInt = BlindCtxInt{ctx: &d.party.ctx.ecc, alpha: d.alpha, sk: d.aesKey, h2c: d.party.h2c}
	}

	pool := NewWorkerPool(uint64(len(d.party.X)))

	for w, v := range d.party.X {
		idx := GetIndex(w, M.nBits)
		if !unmodified.CheckedRemove(idx) {
			continue
		}
		pool.InChan <- WorkerInput{data: BlindInput{w, v}, id: idx}
	}

	filled := uint64(M.Size()) - unmodified.GetCardinality()
	pool.nJobs = filled

	if sum {
		d.party.RunParallelDelegate(M, pool, BlindEGWorker, ctxSum)
	} else {
		d.party.RunParallelDelegate(M, pool, BlindAESWorker, ctxInt)
	}

	d.party.log.Printf("filled slots=%d (expected=%f) / prop=%f\n", filled, E_FullSlots(float64(M.Size()), float64(len(d.party.X))), float64(filled)/float64(len(d.party.X)))

	pool = NewWorkerPool(unmodified.GetCardinality())
	k := unmodified.Iterator()
	for k.HasNext() {
		pool.InChan <- WorkerInput{id: k.Next(), data: RandomizeInput{}}
	}
	if sum {
		d.party.RunParallelDelegate(M, pool, RandomizeEGDelegateWorker, ctxSum)
	} else {
		d.party.RunParallelDelegate(M, pool, RandomizeAESDelegateWorker, ctxInt)
	}
	d.party.log.Printf("randomized slots=%d\n", unmodified.GetCardinality())
}

func (d *Delegate) DelegateFinish(R *HashMapFinal, sum bool) (int, *EGCiphertext) {
	defer Timer(time.Now(), d.party.log, "DelegateFinish")

	sz := len(R.Q)
	pool := NewWorkerPool(uint64(sz))
	for i := 0; i < sz; i++ {
		pool.InChan <- WorkerInput{id: uint64(i), data: UnblindInput{Q: R.Q[i], AES: R.AES[i]}}
	}

	var res []WorkerOutput
	var ctSum EGCiphertext
	count := 0
	if sum {
		res = pool.Run(UnblindEGWorker, BlindCtxSum{ctx: &d.party.ctx, alpha: d.alpha, pk: d.party.agg_pk, sk: d.party.partial_sk, h2c: d.party.h2c})

		first := true
		for i := 0; i < len(res); i++ {
			data, _ := res[i].data.(*EGCiphertext)
			if data != nil {
				count += 1
				if first {
					ctSum = *data
					first = false
				} else {
					d.party.ctx.EG_AddInplace(&ctSum, data)
				}
			}
		}
	} else {
		res = pool.Run(UnblindAESWorker, BlindCtxInt{ctx: &d.party.ctx.ecc, alpha: d.alpha, sk: d.aesKey, h2c: d.party.h2c})

		for i := 0; i < len(res); i++ {
			data, _ := res[i].data.(string)
			if data != "" {
				count += 1
			}
		}
	}

	if sum {
		return count, &ctSum
	}
	return count, nil
}

func (d *Delegate) JointDecryption(ctSum *EGCiphertext, partials [][]DHElement) big.Int {
	defer Timer(time.Now(), d.party.log, "JointDecryption")

	var result big.Int
	d.party.ctx.EGMP_AggDecrypt(partials, &result, ctSum)
	return result
}
