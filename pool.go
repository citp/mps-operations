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
	for job := range InChan {
		OutChan <- WorkerOutput{job.id, fn(ctx, job.data)}
	}
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
