package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

// #############################################################################

func (p *Party) RunParallel(R *HashMapValues, pool *WorkerPool, fn WorkerFunc, ctx WorkerCtx) {
	res := pool.Run(fn, ctx)
	for i := 0; i < len(res); i++ {
		data, ok := res[i].data.(DHOutput)
		Assert(ok)
		R.data[res[i].id] = HashMapValue(data)
	}
}

func (p *Party) Shuffle(R *HashMapValues) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(R.data), func(i, j int) { R.data[i], R.data[j] = R.data[j], R.data[i] })
	p.log.Printf("shuffled / slots=%d\n", len(R.data))
}

// #############################################################################

func (p *Party) Init(id, n, nBits int, dPath, lPath string) {
	p.id = id
	p.n = n
	p.ctx = NewDHContext()
	p.X = ReadFile(dPath)

	logF, err := os.OpenFile(lPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	Check(err)

	p.log = log.New(logF, fmt.Sprintf("[Party %d] ", p.id), 0)
}

func (p *Party) MPSI_CA(L DHElement, M *HashMapValues, R *HashMapValues) {
	defer Timer(time.Now(), p.log)

	// Initialize R if you are P_1
	if p.id == 1 {
		*R = NewHashMap(M.nBits)
	}

	// For all w in X, DH Reduce M[index(w)] (if P_1), R[index(w)] otherwise
	unmodified := GetEmptyMap(M.Size())
	pool := NewWorkerPool(uint64(len(p.X)))

	for i := 0; i < len(p.X); i++ {
		idx := GetIndex(p.X[i], R.nBits)
		val := R.data[idx]
		if p.id == 1 {
			val = M.data[idx]
		}
		pool.InChan <- WorkerInput{idx, ReduceInput{val.Q, val.S}}
		delete(unmodified, idx)
	}

	dhCtx := DHCtx{&p.ctx, L}
	p.RunParallel(R, pool, ReduceWorker, dhCtx)
	p.log.Printf("reduced / slots=%d\n", len(p.X))

	// Randomize all unmodified indices
	pool = NewWorkerPool(uint64(len(unmodified)))
	for k := range unmodified {
		pool.InChan <- WorkerInput{k, RandomizeInput{}}
	}
	p.RunParallel(R, pool, RandomizeWorker, dhCtx)
	p.log.Printf("randomized / slots=%d\n", len(R.data))

	// Shuffle if you are P_{n-1}
	if p.id == p.n {
		p.Shuffle(R)
	}
}

func (p *Party) MPSIU_CA(L DHElement, M *HashMapValues, R *HashMapValues) {
	defer Timer(time.Now(), p.log)

	// Initialize R if you are P_1
	if p.id == 1 {
		*R = NewHashMap(M.nBits)
	}

	// For all w in X, R[index(w)]= DH_Reduce(M[index(w)])
	unmodified := GetEmptyMap(M.Size())
	pool := NewWorkerPool(uint64(len(p.X)))
	for i := 0; i < len(p.X); i++ {
		idx := GetIndex(p.X[i], M.nBits)
		pool.InChan <- WorkerInput{idx, ReduceInput{p.ctx.HashToCurve(p.X[i]), M.data[idx].S}}
		delete(unmodified, idx)
	}
	dhCtx := DHCtx{&p.ctx, L}
	p.log.Printf("reduced slots=%d\n", len(p.X))
	p.RunParallel(R, pool, ReduceWorker, dhCtx)

	pool = NewWorkerPool(uint64(len(unmodified)))
	var workerFn WorkerFunc
	if p.id == 1 {
		// Randomize all unmodified indices
		for k := range unmodified {
			pool.InChan <- WorkerInput{k, RandomizeInput{}}
		}
		workerFn = RandomizeWorker
	} else {
		// DH Reduce all unmodified indices
		for k := range unmodified {
			pool.InChan <- WorkerInput{k, ReduceInput{R.data[k].Q, R.data[k].S}}
		}
		workerFn = ReduceWorker
	}

	p.RunParallel(R, pool, workerFn, dhCtx)
	op := "randomized"
	if p.id != 1 {
		op = "reduced"
	}
	p.log.Printf("%s unmodified slots=%d\n", op, len(unmodified))

	// Shuffle if you are P_{n-1}
	if p.id == p.n {
		p.Shuffle(R)
	}

}
