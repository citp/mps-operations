package main

import (
	"time"
)

// #############################################################################

func (d *Delegate) Init(id, n, nBits int, dPath, lPath string) {
	d.party.Init(id, n, nBits, dPath, lPath)
	d.sk = d.party.ctx.RandomScalar()
	d.party.ctx.EC_BaseMultiply(d.sk, &d.L)
	M := NewHashMap(nBits)
	d.M = &M
}

func (d *Delegate) Round1() {
	defer Timer(time.Now(), d.party.log)

	pool := NewWorkerPool(uint64(len(d.party.X)))
	empty := GetEmptyMap(d.M.Size())
	for i := 0; i < len(d.party.X); i++ {
		idx := GetIndex(d.party.X[i], d.M.nBits)
		pool.InChan <- WorkerInput{idx, BlindInput{d.party.X[i]}}
		delete(empty, idx)
	}
	d.party.RunParallel(d.M, pool, BlindWorker, BlindCtx{&d.party.ctx, d.sk})

	d.party.log.Printf("empty slots=%d / filled slots=%d\n", len(empty), int(d.M.Size())-len(empty))

	pool = NewWorkerPool(uint64(len(empty)))
	for k := range empty {
		pool.InChan <- WorkerInput{k, RandomizeInput{}}
	}
	d.party.RunParallel(d.M, pool, RandomizeWorker, DHCtx{&d.party.ctx, d.L})
}

func (d *Delegate) Round2(R *HashMapValues) float64 {
	defer Timer(time.Now(), d.party.log)

	sz := len(R.data)
	count := 0.0

	pool := NewWorkerPool(uint64(sz))
	for i := 0; i < sz; i++ {
		pool.InChan <- WorkerInput{uint64(i), UnblindInput{R.data[i].Q, R.data[i].S}}
	}
	res := pool.Run(UnblindWorker, BlindCtx{&d.party.ctx, d.sk})

	for i := 0; i < len(res); i++ {
		data, ok := res[i].data.(int)
		Assert(ok)
		count += float64(data)
	}
	return count
}
