package main

import (
	"crypto/elliptic"
	"log"
	"math/big"
	"time"
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
	party  Party
	alpha  DHScalar
	L      DHElement
	aesKey []byte
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

type Ciphertext struct {
	EG  EGCiphertext
	AES []byte
}

type HashMapValues struct {
	DHData []HashMapValue
	// EGData []EGCiphertext
	EncData []Ciphertext
	nBits   int
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
	nJobs   uint64
	InChan  InputChannel
	OutChan OutputChannel
}

type Stopwatch struct {
	start time.Time
}

// #############################################################################

type BlindInput struct {
	w string
	v int
}

type H2CInput string

type RandomizeInput struct{}

type HashAndReduceInput struct {
	w string
	P DHElement
}

type ReduceInput struct {
	H, P DHElement
}

type EncryptInput struct {
	ct *Ciphertext
	S  *DHElement
}

type UnblindInput struct {
	Q   DHElement
	AES []byte
}

type BlindCtxInt struct {
	ctx   *DHContext
	alpha DHScalar
	sk    []byte
}

type BlindCtxSum struct {
	ctx   *EGContext
	alpha DHScalar
	pk    DHElement
	sk    DHScalar
}

type H2CCtx elliptic.Curve

type DHCtx struct {
	ctx *DHContext
	L   DHElement
}

type EncryptCtx struct {
	ctx *EGContext
	apk *DHElement
}

type H2COutput DHElement

type DHOutput struct {
	Q, S DHElement
	Ct   Ciphertext
}

type EncryptOutput []byte

type UnblindOutput int

// #############################################################################
