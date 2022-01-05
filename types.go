package main

import (
	"crypto/elliptic"
	"log"
	"math/big"
	"time"

	"github.com/schollz/progressbar/v3"
)

// #############################################################################

type Party struct {
	id, n, nBits int
	ctx          DHContext
	X            []string
	log          *log.Logger
	showP        bool
}

type Delegate struct {
	party Party
	sk    DHScalar
	L     DHElement
}

// #############################################################################

type DHContext struct {
	Curve elliptic.Curve
	G     DHElement
}

type DHScalar *big.Int
type DHElement struct {
	x *big.Int
	y *big.Int
}

type HashMapValues struct {
	data  []HashMapValue
	nBits int
}

type HashMapValue struct {
	Q, S DHElement
}

type Set struct {
	data map[string]bool
}

type ChanMsg struct {
	id   uint64
	data interface{}
}

type WorkerInput ChanMsg
type InputChannel chan WorkerInput
type WorkerOutput ChanMsg
type OutputChannel chan WorkerOutput
type WorkerCtx interface{}
type WorkerFunc func(WorkerCtx, interface{}) interface{}

type WorkerPool struct {
	bar     *progressbar.ProgressBar
	nJobs   uint64
	InChan  InputChannel
	OutChan OutputChannel
}

type Stopwatch struct {
	start time.Time
}

// #############################################################################

type RandomizeInput struct{}

type ReduceInput struct {
	H, P DHElement
}

type BlindInput struct {
	x string
}

type UnblindInput struct {
	Q DHElement
	S DHElement
}

type DHCtx struct {
	ctx *DHContext
	L   DHElement
}

type BlindCtx struct {
	ctx *DHContext
	sk  DHScalar
}

type DHOutput struct {
	Q, S DHElement
}

type UnblindOutput int
