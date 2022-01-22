package main

import (
	"fmt"
	"log"
	"math/big"
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
		R.DHData[res[i].id] = HashMapValue{data.Q, data.S}
	}
}

func (p *Party) Encrypt(M, R *HashMapValues) HashMapFinal {
	var final HashMapFinal
	length := len(R.DHData)
	Assert(length == len(R.EGData))

	final.Q = make([]DHElement, length)
	final.AES = make([][]byte, length)

	for i := 0; i < length; i++ {
		final.Q[i].x = new(big.Int).Set(R.DHData[i].Q.x)
		final.Q[i].y = new(big.Int).Set(R.DHData[i].Q.y)
		final.AES[i] = AEAD_Encrypt(p.ctx.EG_Serialize(&M.EGData[i]), SHA256(R.DHData[i].S.Serialize()))
	}
	p.Shuffle(&final)
	return final
}

func (p *Party) Shuffle(R *HashMapFinal) {
	// rand.Seed(time.Now().UnixNano())
	rand.Seed(0)
	rand.Shuffle(len(R.Q), func(i, j int) {
		R.Q[i], R.Q[j] = R.Q[j], R.Q[i]
		R.AES[i], R.AES[j] = R.AES[j], R.AES[i]
	})
	p.log.Printf("shuffled / slots=%d\n", len(R.Q))
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
	ret += 2 * nElems * uint64(R.DHData[0].S.ByteSize())
	return ret
}

// #############################################################################

func (p *Party) Init(id, n, nBits int, dPath, lPath string, showP bool, ctx *EGContext) {
	p.id = id
	p.n = n
	p.nBits = nBits
	p.ctx = *ctx
	p.X = ReadFile(dPath)
	p.showP = showP

	logF, err := os.OpenFile(lPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	Check(err)

	p.log = log.New(logF, fmt.Sprintf("[Party %d] ", p.id), 0)
	p.partial_sk = ctx.ecc.RandomScalar()
	// fmt.Println("Partial:", id, p.partial_sk.Text(10))
}

func (p *Party) Partial_PubKey() DHElement {
	var pk DHElement
	p.ctx.EGMP_PubKey(p.partial_sk, &pk)
	return pk
}

func (p *Party) Set_AggPubKey(pks []DHElement) {
	p.agg_pk.x = new(big.Int).Set(pks[0].x)
	p.agg_pk.y = new(big.Int).Set(pks[0].y)

	for i := 1; i <= p.n; i++ {
		p.ctx.ecc.EC_Add(p.agg_pk, pks[i], &p.agg_pk)
	}
}

func (p *Party) Partial_Decrypt(ct *EGCiphertext) []DHElement {
	return p.ctx.EGMP_Decrypt(p.partial_sk, ct)
}

// #############################################################################

func (p *Party) MPSI_CA(L DHElement, M *HashMapValues, R *HashMapValues) *HashMapFinal {
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

	// for i := 0; i < len(p.X); i++ {
	for w := range p.X {
		idx := GetIndex(w, R.nBits)
		if !unmodified.Contains(idx) {
			continue
		}
		val := R.DHData[idx]
		if p.id == 1 {
			HashToCurve_13(w, &val.Q, p.ctx.ecc.Curve)
			val.S = M.DHData[idx].S
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

	dhCtx := DHCtx{&p.ctx.ecc, L}
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
		ret := p.Encrypt(M, R)
		return &ret
	} else {
		return nil
	}
}

func (p *Party) MPSIU_CA(L DHElement, M *HashMapValues, R *HashMapValues) *HashMapFinal {
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

	// for i := 0; i < len(p.X); i++ {
	for w := range p.X {
		idx := GetIndex(w, M.nBits)
		if !unmodified.Contains(idx) {
			continue
		}
		HashToCurve_13(w, &inputData.H, p.ctx.ecc.Curve)
		inputData.P = M.DHData[idx].S
		inputs = append(inputs, WorkerInput{idx, inputData})
		unmodified.Remove(idx)
	}
	pool := NewWorkerPool(uint64(len(inputs)), bar)
	for _, v := range inputs {
		pool.InChan <- v
	}
	fmt.Println("njobs", p.id, len(inputs))

	dhCtx := DHCtx{&p.ctx.ecc, L}
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
			pool.InChan <- WorkerInput{idx, ReduceInput{R.DHData[idx].Q, R.DHData[idx].S}}
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
		ret := p.Encrypt(M, R)
		return &ret
	} else {
		return nil
	}
}
