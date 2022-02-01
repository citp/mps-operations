package main

import (
	"crypto/elliptic"
	"log"
	"math/big"
	"time"
)

// #############################################################################

type Party struct {
	ctx          EGContext
	agg_pk       DHElement
	X            map[string]int
	id, n, nBits int
	log          *log.Logger
	partial_sk   *big.Int
	h2c          *HtoCParams
	showP        bool
}

type Delegate struct {
	party  Party
	L      DHElement
	alpha  DHScalar
	aesKey []byte
}

// #############################################################################

type DHContext struct {
	G     DHElement
	Curve elliptic.Curve
}

type DHScalar *big.Int
type DHElement struct {
	x, y *big.Int
}

type EGContext struct {
	ecc     DHContext
	table   map[string]big.Int
	n, Ny   []*big.Int
	N       *big.Int
	nModuli uint
}

type EGCiphertext struct {
	c1, c2 []DHElement
}

type Ciphertext struct {
	EG  EGCiphertext
	AES []byte
}

type HashMapValues struct {
	EncData []Ciphertext
	DHData  []HashMapValue
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
	InChan  InputChannel
	OutChan OutputChannel
	nJobs   uint64
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

type MPSIReduceInput struct {
	w            string
	Rj0, Rj1, Mj DHElement
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
	h2c   *HtoCParams
}

type BlindCtxSum struct {
	ctx   *EGContext
	alpha DHScalar
	pk    DHElement
	sk    DHScalar
	h2c   *HtoCParams
}

type H2CCtx elliptic.Curve

type DHCtx struct {
	ctx  *DHContext
	L    DHElement
	isP1 bool
	h2c  *HtoCParams
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
