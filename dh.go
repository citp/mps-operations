package main

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"math/big"
	"strings"
)

// #############################################################################

func NewDHContext(ret *DHContext) {
	ret.Curve = elliptic.P256()
	ret.G = DHElement{ret.Curve.Params().Gx, ret.Curve.Params().Gy}
}

// func NewDHElement(e *DHElement) {
// 	*e = DHElement{big.NewInt(0), big.NewInt(0)}
// }

func (ctx *DHContext) EC_BaseMultiply(s DHScalar, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.ScalarBaseMult((*s).Bytes())
}

func (ctx *DHContext) EC_Multiply(s DHScalar, p DHElement, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.ScalarMult(p.x, p.y, (*s).Bytes())
}

func (ctx *DHContext) EC_Add(a, b DHElement, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.Add(a.x, a.y, b.x, b.y)
}

func (ctx *DHContext) DH_Reduce(L, T, P DHElement) (DHElement, DHElement) {
	var t1, t2, Q, S DHElement
	beta := ctx.RandomScalar()
	gamma := ctx.RandomScalar()
	ctx.EC_Multiply(beta, T, &t1)
	ctx.EC_Multiply(gamma, ctx.G, &t2)
	ctx.EC_Add(t1, t2, &Q)
	ctx.EC_Multiply(beta, P, &t1)
	ctx.EC_Multiply(gamma, L, &t2)
	ctx.EC_Add(t1, t2, &S)
	return Q, S
}

// #############################################################################

// func (ctx *DHContext) LegendreSym(z *big.Int) *big.Int {
// 	p := ctx.Curve.Params().P
// 	exp := new(big.Int).Sub(p, big.NewInt(1))
// 	exp = exp.Div(exp, big.NewInt(2))
// 	return new(big.Int).Exp(z, exp, p)
// }

func (ctx *DHContext) SquareRootModP(z *big.Int) *big.Int {
	p := ctx.Curve.Params().P
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp = exp.Div(exp, big.NewInt(4))
	return new(big.Int).Exp(z, exp, p)
}

func (ctx *DHContext) YfromX(x *big.Int) *big.Int {
	p := ctx.Curve.Params().P
	three := big.NewInt(3)
	x3 := new(big.Int).Exp(x, three, p)
	y2 := new(big.Int).Sub(x3, new(big.Int).Mul(three, x))
	y2 = y2.Add(y2, ctx.Curve.Params().B)
	y2 = y2.Mod(y2, p)
	return ctx.SquareRootModP(y2)
}

func (ctx *DHContext) HashToCurve(s string, e *DHElement) {
	buf := []byte(s)
	p := ctx.Curve.Params().P
	count := 0
	for {
		// bufHash := Blake2b(buf)
		bufHash := BLAKE2B(buf, "HashToCurve")
		x := new(big.Int).SetBytes(bufHash)
		x = x.Mod(x, p)
		y := ctx.YfromX(x)
		if ctx.Curve.IsOnCurve(x, y) {
			e.x, e.y = x, y
			// fmt.Println("count", count)
			return
			// return DHElement{x, y}
		}
		count += 1
		buf = bufHash
		// buf = Blake2b(bufHash)
	}
}

func (ctx *DHContext) RandomScalar() *big.Int {
	ret, err := crand.Int(crand.Reader, ctx.Curve.Params().P)
	Check(err)
	return ret
}

func (ctx *DHContext) RandomElement(ret *DHElement) {
	ctx.EC_BaseMultiply(ctx.RandomScalar(), ret)
}

// #############################################################################

func (p *DHElement) String() string {
	return p.x.Text(16) + "," + p.y.Text(16)
}

func (p *DHElement) Serialize() []byte {
	ret := p.x.Bytes()
	sign := p.y.Sign() + 2
	return append(ret, byte(sign))
}

func DHElementFromBytes(ctx *DHContext, b []byte) DHElement {
	Assert(len(b) == 33)
	x := new(big.Int).SetBytes(b[:32])
	y := ctx.YfromX(x)
	if int(b[32])-2 != y.Sign() {
		y.Neg(y)
	}
	return DHElement{x, y}
}

func (p *DHElement) ByteSize() int {
	return 33
}

func BigIntFrom(s string) *big.Int {
	ret := big.NewInt(0)
	ret, ok := ret.SetString(s, 16)
	if !ok {
		panic("Could not deserialize")
	}

	return ret
}

func DHElementFromString(s string) DHElement {
	strs := strings.Split(s, ",")
	return DHElement{BigIntFrom(strs[0]), BigIntFrom(strs[1])}
}
