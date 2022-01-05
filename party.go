package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
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
	// rand.Seed(time.Now().UnixNano())
	rand.Seed(0)
	rand.Shuffle(len(R.data), func(i, j int) { R.data[i], R.data[j] = R.data[j], R.data[i] })
	p.log.Printf("shuffled / slots=%d\n", len(R.data))
}

func (p *Party) TComputation(proto int, R *HashMapValues) uint64 {
	rSize := R.Size()
	xSize := uint64(len(p.X))
	nMuls := uint64(0)
	nReducs := uint64(0)
	nRandoms := uint64(0)
	nBlinds := uint64(0)

	if p.id == 0 {
		nMuls += 1
		nBlinds += xSize
		nRandoms += (rSize - xSize)
		nBlinds += rSize
	} else {
		nReducs += xSize
		if proto == 1 {
			nRandoms += (rSize - xSize)
		} else if proto == 2 {
			if p.id == 1 {
				nRandoms += (rSize - xSize)
			} else {
				nReducs += (rSize - xSize)
			}
		}
	}

	nMuls = nBlinds + nRandoms + (4 * nReducs)
	return nMuls
}

func (p *Party) TCommunication(R *HashMapValues) uint64 {
	ret := uint64(0)
	nElems := 2*R.Size() + 1
	ret += 2 * nElems * uint64(R.data[0].S.ByteSize())
	return ret
}

// #############################################################################

func (p *Party) Init(id, n, nBits int, dPath, lPath string, showP bool) {
	p.id = id
	p.n = n
	p.nBits = nBits
	NewDHContext(&p.ctx)
	p.X = ReadFile(dPath)
	p.showP = showP

	logF, err := os.OpenFile(lPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	Check(err)

	p.log = log.New(logF, fmt.Sprintf("[Party %d] ", p.id), 0)
}

func (p *Party) MPSI_CA(L DHElement, M *HashMapValues, R *HashMapValues) {
	defer Timer(time.Now(), p.log)
	var bar *progressbar.ProgressBar

	// Initialize R if you are P_1
	if p.id == 1 {
		*R = NewHashMap(M.nBits)
	}

	if p.showP {
		bar = NewProgressBar(len(p.X), "cyan", "[1/2] Reducing")
	}

	// For all w in X, DH Reduce M[index(w)] (if P_1), R[index(w)] otherwise
	unmodified := GetBitMap(M.Size())
	inputs := make([]WorkerInput, 0)

	for i := 0; i < len(p.X); i++ {
		idx := GetIndex(p.X[i], R.nBits)
		if !unmodified.Contains(idx) {
			continue
		}
		val := R.data[idx]
		if p.id == 1 {
			p.ctx.HashToCurve(p.X[i], &val.Q)
			val.S = M.data[idx].S
		}
		inputs = append(inputs, WorkerInput{idx, ReduceInput{val.Q, val.S}})
		unmodified.Remove(idx)
	}

	pool := NewWorkerPool(uint64(len(inputs)), bar)
	for _, v := range inputs {
		pool.InChan <- v
	}
	fmt.Println("njobs", p.id, len(inputs))

	modified := M.Size() - unmodified.GetCardinality()
	p.log.Printf("modified slots=%d (expected=%f) / prop=%f\n", modified, E_FullSlots(float64(int(1)<<p.nBits), float64(len(p.X))), float64(modified)/float64(len(p.X)))

	dhCtx := DHCtx{&p.ctx, L}
	p.RunParallel(R, pool, ReduceWorker, dhCtx)

	// Randomize all unmodified indices
	if p.showP {
		bar = NewProgressBar(int(unmodified.GetCardinality()), "cyan", "[2/2] Randomizing")
	}
	pool = NewWorkerPool(uint64(unmodified.GetCardinality()), bar)
	k := unmodified.Iterator()
	for k.HasNext() {
		pool.InChan <- WorkerInput{k.Next(), RandomizeInput{}}
	}
	p.RunParallel(R, pool, RandomizeWorker, dhCtx)
	p.log.Printf("randomized slots=%d\n", unmodified.GetCardinality())

	// Shuffle if you are P_{n-1}
	if p.id == p.n {
		p.Shuffle(R)
	}
}

func (p *Party) MPSIU_CA(L DHElement, M *HashMapValues, R *HashMapValues) {
	defer Timer(time.Now(), p.log)
	var bar *progressbar.ProgressBar

	// Initialize R if you are P_1
	if p.id == 1 {
		*R = NewHashMap(M.nBits)
	}

	// For all w in X, R[index(w)]= DH_Reduce(M[index(w)])
	if p.showP {
		bar = NewProgressBar(len(p.X), "cyan", "[1/2] Reducing")
	}
	unmodified := GetBitMap(M.Size())
	var inputData ReduceInput
	inputs := make([]WorkerInput, 0)

	for i := 0; i < len(p.X); i++ {
		idx := GetIndex(p.X[i], M.nBits)
		if !unmodified.Contains(idx) {
			continue
		}
		p.ctx.HashToCurve(p.X[i], &inputData.H)
		inputData.P = M.data[idx].S
		inputs = append(inputs, WorkerInput{idx, inputData})
		unmodified.Remove(idx)
	}
	pool := NewWorkerPool(uint64(len(inputs)), bar)
	for _, v := range inputs {
		pool.InChan <- v
	}
	fmt.Println("njobs", p.id, len(inputs))

	dhCtx := DHCtx{&p.ctx, L}
	modified := M.Size() - unmodified.GetCardinality()
	p.log.Printf("modified slots=%d (expected=%f) / prop=%f\n", modified, E_FullSlots(float64(int(1)<<p.nBits), float64(len(p.X))), float64(modified)/float64(len(p.X)))
	p.RunParallel(R, pool, ReduceWorker, dhCtx)

	if p.showP {
		if p.id == 1 {
			bar = NewProgressBar(int(unmodified.GetCardinality()), "cyan", "[1/2] Randomizing")
		} else {
			bar = NewProgressBar(int(unmodified.GetCardinality()), "cyan", "[1/2] Reducing")
		}
	}

	pool = NewWorkerPool(unmodified.GetCardinality(), bar)
	k := unmodified.Iterator()
	var workerFn WorkerFunc
	if p.id == 1 {
		// Randomize all unmodified indices
		for k.HasNext() {
			pool.InChan <- WorkerInput{k.Next(), RandomizeInput{}}
		}
		workerFn = RandomizeWorker
	} else {
		// DH Reduce all unmodified indices
		for k.HasNext() {
			idx := k.Next()
			pool.InChan <- WorkerInput{idx, ReduceInput{R.data[idx].Q, R.data[idx].S}}
		}
		workerFn = ReduceWorker
	}

	p.RunParallel(R, pool, workerFn, dhCtx)
	op := "randomized"
	if p.id != 1 {
		op = "reduced"
	}
	p.log.Printf("%s unmodified slots=%d\n", op, unmodified.GetCardinality())

	// Shuffle if you are P_{n-1}
	if p.id == p.n {
		p.Shuffle(R)
	}
}
