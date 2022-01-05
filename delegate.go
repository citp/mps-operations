package main

import (
	"time"

	"github.com/schollz/progressbar/v3"
)

// #############################################################################

func (d *Delegate) Init(id, n, nBits int, dPath, lPath string, showP bool) {
	d.party.Init(id, n, nBits, dPath, lPath, showP)
	d.sk = d.party.ctx.RandomScalar()
	d.party.ctx.EC_BaseMultiply(d.sk, &d.L)
}

func (d *Delegate) Round1(M *HashMapValues) {
	defer Timer(time.Now(), d.party.log)
	var bar *progressbar.ProgressBar

	if d.party.showP {
		bar = NewProgressBar(len(d.party.X), "cyan", "[1/2] Blinding")
	}

	pool := NewWorkerPool(uint64(len(d.party.X)), bar)
	unmodified := GetBitMap(M.Size())
	for i := 0; i < len(d.party.X); i++ {
		idx := GetIndex(d.party.X[i], M.nBits)
		pool.InChan <- WorkerInput{idx, BlindInput{d.party.X[i]}}
		unmodified.Remove(idx)
	}
	d.party.RunParallel(M, pool, BlindWorker, BlindCtx{&d.party.ctx, d.sk})

	filled := uint64(M.Size()) - unmodified.GetCardinality()
	d.party.log.Printf("filled slots=%d (expected=%f) / prop=%f\n", filled, E_FullSlots(float64(M.Size()), float64(len(d.party.X))), float64(filled)/float64(len(d.party.X)))

	if d.party.showP {
		bar = NewProgressBar(int(unmodified.GetCardinality()), "cyan", "[2/2] Randomizing")
	}
	pool = NewWorkerPool(unmodified.GetCardinality(), bar)
	k := unmodified.Iterator()
	for k.HasNext() {
		pool.InChan <- WorkerInput{k.Next(), RandomizeInput{}}
	}
	d.party.RunParallel(M, pool, RandomizeWorker, DHCtx{&d.party.ctx, d.L})
}

func (d *Delegate) Round2(R *HashMapValues) float64 {
	defer Timer(time.Now(), d.party.log)
	var bar *progressbar.ProgressBar

	sz := len(R.data)
	count := 0.0

	if d.party.showP {
		bar = NewProgressBar(sz, "cyan", "[1/1] Unblinding")
	}
	pool := NewWorkerPool(uint64(sz), bar)
	for i := 0; i < sz; i++ {
		pool.InChan <- WorkerInput{uint64(i), UnblindInput{R.data[i].Q, R.data[i].S}}
	}
	res := pool.Run(UnblindWorker, BlindCtx{&d.party.ctx, d.sk})

	for i := 0; i < len(res); i++ {
		data, ok := res[i].data.(int)
		Assert(ok)
		count += float64(data)
	}

	// fmt.Printf("ExpectedCollidedIndices=%f", ExpectedCollidedIndices(d.nBits, d.party.n, len(d.party.X)))
	return count
}
