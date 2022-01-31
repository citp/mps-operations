package main

import (
	"fmt"
	"log"
	"math/big"
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
		R.DHData[res[i].id] = HashMapValue{data.Q, data.S}
	}
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
	logF, err := os.OpenFile(lPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	Panic(err)
	p.log = log.New(logF, fmt.Sprintf("[Party %d] ", id), 0)
	defer Timer(time.Now(), p.log, "Init")

	p.id = id
	p.n = n
	p.nBits = nBits
	p.ctx = *ctx
	p.X = ReadFile(dPath)
	p.showP = showP
	p.partial_sk = ctx.ecc.RandomScalar()
	p.h2c, err = NewHtoCParams("P256_XMD:SHA-256_SSWU_RO_")
	Panic(err)
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

// func (p *Party) Initialize_R(M *HashMapValues, R *HashMapValues) {
// 	if p.id != 1 {
// 		return
// 	}

// 	defer Timer(time.Now(), p.log, "Initialize_R")

// 	*R = NewHashMap(M.nBits)
// 	inputs := make([]WorkerInput, 0)

// 	unmodified := GetBitMap(M.Size())
// 	for w := range p.X {
// 		idx := GetIndex(w, R.nBits)
// 		if !unmodified.Contains(idx) {
// 			continue
// 		}
// 		inputs = append(inputs, WorkerInput{idx, H2CInput(w)})
// 		R.DHData[idx].S = M.DHData[idx].S
// 		unmodified.Remove(idx)
// 	}

// 	pool := NewWorkerPool(uint64(len(inputs)))
// 	for _, v := range inputs {
// 		pool.InChan <- v
// 	}

// 	res := pool.Run(H2CWorker, H2CCtx(p.ctx.ecc.Curve))
// 	Assert(len(res) == len(inputs))

// 	for i := 0; i < len(res); i++ {
// 		data, ok := res[i].data.(H2COutput)
// 		Assert(ok)
// 		R.DHData[res[i].id].Q = DHElement(data)
// 	}
// }

func (p *Party) BlindEncrypt(M, R *HashMapValues, sum bool) *HashMapFinal {
	if p.id != p.n {
		return nil
	}

	defer Timer(time.Now(), p.log, "BlindEncrypt")

	var final HashMapFinal
	length := len(R.DHData)
	Assert(length == len(R.EncData))

	final.Q = make([]DHElement, length)
	final.AES = make([][]byte, length)

	pool := NewWorkerPool(uint64(length))
	for i := 0; i < length; i++ {
		final.Q[i] = R.DHData[i].Q
		// final.Q[i].x = new(big.Int).Set(R.DHData[i].Q.x)
		// final.Q[i].y = new(big.Int).Set(R.DHData[i].Q.y)
		pool.InChan <- WorkerInput{uint64(i), EncryptInput{&M.EncData[i], &R.DHData[i].S}}
	}
	var res []WorkerOutput
	if sum {
		res = pool.Run(EncryptEGWorker, EncryptCtx{&p.ctx, &p.agg_pk})
	} else {
		res = pool.Run(EncryptAESWorker, nil)
	}
	Assert(len(res) == length)

	for i := 0; i < len(res); i++ {
		data, ok := res[i].data.(EncryptOutput)
		Assert(ok)
		final.AES[res[i].id] = data
	}
	p.Shuffle(&final)
	return &final
}

func (p *Party) Shuffle(R *HashMapFinal) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(R.Q), func(i, j int) {
		R.Q[i], R.Q[j] = R.Q[j], R.Q[i]
		R.AES[i], R.AES[j] = R.AES[j], R.AES[i]
	})
	p.log.Printf("shuffled slots=%d\n", len(R.Q))
}

// #############################################################################

// Multiparty Private Set Intersection (optionally, sum)
func (p *Party) MPSI(L DHElement, M *HashMapValues, R *HashMapValues, sum bool) *HashMapFinal {
	proto := "MPSI_S"
	if !sum {
		proto = "MPSI"
	}
	defer Timer(time.Now(), p.log, proto)

	// Initialize R if you are P_1
	if p.id == 1 {
		*R = NewHashMap(M.nBits)
	}
	// p.Initialize_R(M, R)

	// For all w in X, DH Reduce R[index(w)]
	unmodified := GetBitMap(M.Size())
	inputs := make([]WorkerInput, 0)

	for w := range p.X {
		idx := GetIndex(w, R.nBits)
		if !unmodified.Contains(idx) {
			continue
		}
		// inputs = append(inputs, WorkerInput{idx, ReduceInput{R.DHData[idx].Q, R.DHData[idx].S}})
		inputs = append(inputs, WorkerInput{idx, MPSIReduceInput{w, R.DHData[idx].Q, R.DHData[idx].S, M.DHData[idx].S}})
		unmodified.Remove(idx)
	}

	pool := NewWorkerPool(uint64(len(inputs)))
	for _, v := range inputs {
		pool.InChan <- v
	}
	fmt.Println("njobs", p.id, len(inputs))

	modified := M.Size() - unmodified.GetCardinality()
	p.log.Printf("modified slots=%d (expected=%f) / prop=%f\n", modified, E_FullSlots(float64(int(1)<<p.nBits), float64(len(p.X))), float64(modified)/float64(len(p.X)))

	dhCtx := DHCtx{&p.ctx.ecc, L, p.id == 1, p.h2c}
	// p.RunParallel(R, pool, ReduceWorker, dhCtx)
	p.RunParallel(R, pool, MPSIReduceWorker, dhCtx)

	// Randomize all unmodified indices
	pool = NewWorkerPool(uint64(unmodified.GetCardinality()))
	k := unmodified.Iterator()
	for k.HasNext() {
		pool.InChan <- WorkerInput{k.Next(), RandomizeInput{}}
	}
	p.RunParallel(R, pool, RandomizeWorker, dhCtx)
	p.log.Printf("randomized slots=%d\n", unmodified.GetCardinality())

	// Shuffle and return B if you are P_{n-1}
	return p.BlindEncrypt(M, R, sum)
}

func (p *Party) MPSIU(L DHElement, M *HashMapValues, R *HashMapValues, sum bool) *HashMapFinal {
	proto := "MPSIU_S"
	if !sum {
		proto = "MPSIU"
	}
	defer Timer(time.Now(), p.log, proto)

	// Initialize R if you are P_1
	if p.id == 1 {
		*R = NewHashMap(M.nBits)
	}
	// p.Initialize_R(M, R)

	// For all w in X, R[index(w)]= DH_Reduce(M[index(w)])
	unmodified := GetBitMap(M.Size())
	inputs := make([]WorkerInput, 0)
	for w := range p.X {
		idx := GetIndex(w, M.nBits)
		if !unmodified.Contains(idx) {
			continue
		}
		inputs = append(inputs, WorkerInput{idx, HashAndReduceInput{w, M.DHData[idx].S}})
		unmodified.Remove(idx)
	}
	pool := NewWorkerPool(uint64(len(inputs)))
	for _, v := range inputs {
		pool.InChan <- v
	}
	fmt.Println("njobs", p.id, len(inputs))

	dhCtx := DHCtx{&p.ctx.ecc, L, p.id == 1, p.h2c}
	modified := M.Size() - unmodified.GetCardinality()
	p.log.Printf("modified slots=%d (expected=%f) / prop=%f\n", modified, E_FullSlots(float64(int(1)<<p.nBits), float64(len(p.X))), float64(modified)/float64(len(p.X)))
	p.RunParallel(R, pool, HashAndReduceWorker, dhCtx)

	pool = NewWorkerPool(unmodified.GetCardinality())
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

	// Shuffle and return B if you are P_{n-1}
	return p.BlindEncrypt(M, R, sum)
}
