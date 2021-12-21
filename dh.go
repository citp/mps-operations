package main

import (
	"crypto/elliptic"
	"math/big"
	"strings"
)

// #############################################################################

func NewDHContext() DHContext {
	var ret DHContext
	ret.Curve = elliptic.P256()
	ret.G = DHElement{ret.Curve.Params().Gx, ret.Curve.Params().Gy}
	return ret
}

func NewDHElement() DHElement {
	return DHElement{big.NewInt(0), big.NewInt(0)}
}

func (ctx *DHContext) EC_BaseMultiply(s DHScalar, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.ScalarBaseMult((*s).Bytes())
}

func (ctx *DHContext) EC_Multiply(s DHScalar, p DHElement, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.ScalarMult(p.x, p.y, (*s).Bytes())
}

func (ctx *DHContext) EC_Add(a, b DHElement, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.Add(a.x, a.y, b.x, b.y)
}

func (ctx *DHContext) DH_Reduce(P, L, H DHElement, beta, gamma *DHScalar, Q, S *DHElement) {
	var t1, t2 DHElement
	*beta = RandomScalar(ctx.Curve.Params().P)
	*gamma = RandomScalar(ctx.Curve.Params().P)
	ctx.EC_Multiply(*beta, H, &t1)
	ctx.EC_Multiply(*gamma, ctx.G, &t2)
	ctx.EC_Add(t1, t2, Q)
	ctx.EC_Multiply(*beta, P, &t1)
	ctx.EC_Multiply(*gamma, L, &t2)
	ctx.EC_Add(t1, t2, S)
}

// #############################################################################

func (ctx *DHContext) LegendreSym(z *big.Int) *big.Int {
	p := ctx.Curve.Params().P
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp = exp.Div(exp, big.NewInt(2))
	return new(big.Int).Exp(z, exp, p)
}

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

func (ctx *DHContext) HashToCurve(s string) DHElement {
	buf := []byte(s)
	p := ctx.Curve.Params().P
	for {
		bufHash := Blake2b(buf)
		x := new(big.Int).SetBytes(bufHash)
		x = x.Mod(x, p)
		y := ctx.YfromX(x)
		if ctx.Curve.IsOnCurve(x, y) {
			return DHElement{x, y}
		}
		buf = Blake2b(bufHash)
	}
}

func (ctx *DHContext) RandomScalar() *big.Int {
	return RandomScalar(ctx.Curve.Params().P)
}

func (ctx *DHContext) RandomElement(ret *DHElement) {
	ctx.EC_BaseMultiply(ctx.RandomScalar(), ret)
}

// #############################################################################

func (p *DHElement) String() string {
	return p.x.Text(16) + "," + p.y.Text(16)
}

func BigIntFrom(s string) *big.Int {
	ret := big.NewInt(0)
	ret, ok := ret.SetString(s, 16)
	if !ok {
		panic("Could not deserialize")
	}

	return ret
}

func DHElementFrom(s string) DHElement {
	strs := strings.Split(s, ",")
	return DHElement{BigIntFrom(strs[0]), BigIntFrom(strs[1])}
}
