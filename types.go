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
	aesKey []byte
	L      DHElement
	alpha  DHScalar
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
	n, Ny   []*big.Int
	table   map[string]big.Int
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
	data interface{}
	id   uint64
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

type HashFunction func([]byte) []byte

type HtoCParams struct {
	DST        string
	A, B, q, Z *big.Int
	k, m, L, h int
	H          HashFunction
	b, s       int
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
	AES []byte
	Q   DHElement
}

type BlindCtxInt struct {
	sk    []byte
	ctx   *DHContext
	alpha DHScalar
	h2c   *HtoCParams
}

type BlindCtxSum struct {
	pk    DHElement
	ctx   *EGContext
	alpha DHScalar
	sk    DHScalar
	h2c   *HtoCParams
}

type H2CCtx elliptic.Curve

type DHCtx struct {
	L    DHElement
	ctx  *DHContext
	h2c  *HtoCParams
	isP1 bool
}

type EncryptCtx struct {
	ctx *EGContext
	apk *DHElement
}

type H2COutput DHElement

type DHOutput struct {
	Ct   Ciphertext
	Q, S DHElement
}

type EncryptOutput []byte

type UnblindOutput int

// #############################################################################
