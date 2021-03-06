package main

import (
	"runtime"
	"sync"
)

// #############################################################################

func NewWorkerPool(nJobs uint64) *WorkerPool {
	return &WorkerPool{
		make(InputChannel, nJobs),
		make(OutputChannel, nJobs),
		nJobs,
	}
}

func StartWorker(fn WorkerFunc, ctx WorkerCtx, InChan InputChannel, OutChan OutputChannel) {
	for {
		job := <-InChan
		if job.id == 0 && job.data == nil {
			break
		}
		OutChan <- WorkerOutput{id: job.id, data: fn(ctx, job.data)}
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
