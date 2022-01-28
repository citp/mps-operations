package main

import (
	"runtime"
	"sync"
)

// #############################################################################

func NewWorkerPool(nJobs uint64) *WorkerPool {
	return &WorkerPool{
		nJobs,
		make(InputChannel, nJobs),
		make(OutputChannel, nJobs),
	}
}

func StartWorker(fn WorkerFunc, ctx WorkerCtx, InChan InputChannel, OutChan OutputChannel) {
	for {
		job := <-InChan
		if job.id == 0 && job.data == nil {
			break
		}
		OutChan <- WorkerOutput{job.id, fn(ctx, job.data)}
	}
	// for job := range InChan {
	// OutChan <- WorkerOutput{job.id, fn(ctx, job.data)}
	// if bar != nil {
	// 	bar.Add(1)
	// }
	// }
}

func (p *WorkerPool) RunBatched(fn WorkerFunc, ctx WorkerCtx, input []WorkerInput, nBatches uint64) []WorkerOutput {
	out := make([]WorkerOutput, p.nJobs)
	batchSz := p.nJobs / nBatches
	Assert(p.nJobs == uint64(len(input)))

	l := runtime.NumCPU()
	var wg sync.WaitGroup
	for i := 0; i < l; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			StartWorker(fn, ctx, p.InChan, p.OutChan)
		}()
	}

	for i := uint64(0); i < nBatches; i++ {
		for j := uint64(0); j < batchSz; j++ {
			p.InChan <- input[j]
		}
		// res = append(res, p.RunN(fn, ctx, batchSz)...)
		for j := uint64(0); j < batchSz; j++ {
			out[i*batchSz+j] = <-p.OutChan
		}
	}
	close(p.InChan)
	wg.Wait()
	close(p.OutChan)

	return out
}

func (p *WorkerPool) RunN(fn WorkerFunc, ctx WorkerCtx, nJobs uint64) []WorkerOutput {
	l := runtime.NumCPU()
	var wg sync.WaitGroup
	for i := 0; i < l; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			StartWorker(fn, ctx, p.InChan, p.OutChan)
		}()
	}

	// close(p.InChan)
	// wg.Wait()
	out := make([]WorkerOutput, nJobs)
	for i := uint64(0); i < nJobs; i++ {
		out[i] = <-p.OutChan
	}

	// close(p.OutChan)
	return out
}

func (p *WorkerPool) Run(fn WorkerFunc, ctx WorkerCtx) []WorkerOutput {
	l := runtime.NumCPU()
	var wg sync.WaitGroup
	for i := 0; i < l; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			StartWorker(fn, ctx, p.InChan, p.OutChan)
		}()
	}

	close(p.InChan)
	wg.Wait()
	out := make([]WorkerOutput, p.nJobs)
	for i := uint64(0); i < p.nJobs; i++ {
		out[i] = <-p.OutChan
	}

	close(p.OutChan)
	return out
}

// #############################################################################
