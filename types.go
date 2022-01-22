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
	ctx          EGContext
	X            map[string]int
	log          *log.Logger
	showP        bool
	partial_sk   *big.Int
	agg_pk       DHElement
}

type Delegate struct {
	party Party
	alpha DHScalar
	L     DHElement
}

// #############################################################################

type DHContext struct {
	Curve elliptic.Curve
	G     DHElement
}

type DHScalar *big.Int
type DHElement struct {
	x, y *big.Int
}

type EGContext struct {
	ecc     DHContext
	n, Ny   []*big.Int
	N       *big.Int
	nModuli uint
	table   map[string]big.Int
}

type EGCiphertext struct {
	c1, c2 []DHElement
}

type HashMapValues struct {
	DHData []HashMapValue
	EGData []EGCiphertext
	nBits  int
}

type HashMapValue struct {
	Q, S DHElement
}

type HashMapFinal struct {
	Q   []DHElement
	AES [][]byte
}

type Set struct {
	data map[string]int
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
	w string
	v int
}

// type BlindOutput struct {
// 	S  DHElement
// 	Ct EGCiphertext
// }

type UnblindInput struct {
	Q   DHElement
	AES []byte
}

type DHCtx struct {
	ctx *DHContext
	L   DHElement
}

type BlindCtx struct {
	ctx   *EGContext
	alpha DHScalar
	pk    DHElement
	sk    DHScalar
}

type DHOutput struct {
	Q, S DHElement
	Ct   EGCiphertext
}

type UnblindOutput int

// #############################################################################
