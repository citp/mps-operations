package main

import (
	"crypto/elliptic"
	// crand "crypto/rand"
	"math/big"
	"strings"

	"lukechampine.com/frand"
)

// #############################################################################

func NewDHContext(ret *DHContext) {
	ret.Curve = elliptic.P256()
	ret.G = DHElement{ret.Curve.Params().Gx, ret.Curve.Params().Gy}
	// ret.G.x.Set(ret.Curve.Params().Gx)
	// ret.G.y.Set(ret.Curve.Params().Gy)
}

func (ctx *DHContext) EC_BaseMultiply(s DHScalar, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.ScalarBaseMult((*s).Bytes())
}

func (ctx *DHContext) EC_Multiply(s DHScalar, p DHElement, ret *DHElement) {
	ret.x, ret.y = ctx.Curve.ScalarMult(p.x, p.y, (*s).Bytes())
}

func (ctx *DHContext) EC_Negate(a *DHElement) {
	a.y.Neg(a.y)
}

func (ctx *DHContext) EC_Add(a, b DHElement, ret *DHElement) {
	if ret.x == nil {
		ret.x = new(big.Int)
	}
	if ret.y == nil {
		ret.y = new(big.Int)
	}
	// ret.x = new(big.Int)
	// ret.y = new(big.Int)
	// ret.x, ret.y = ctx.Curve.Add(a.x, a.y, b.x, b.y)
	Add(a.x, a.y, b.x, b.y, ret.x, ret.y, ctx.Curve.Params())
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

func (ctx *DHContext) SquareRootModP(y2 *big.Int) *big.Int {
	p := ctx.Curve.Params().P
	var exp big.Int
	exp.Add(p, &one)

	// exp := new(big.Int).Add(p, big.NewInt(1))
	// exp.Div(exp, big.NewInt(4))
	exp.Div(&exp, &four)

	return new(big.Int).Exp(y2, &exp, p)
}

func (ctx *DHContext) YfromX(x *big.Int) *big.Int {
	p := ctx.Curve.Params().P
	var thriceX, x3, y2 big.Int
	// three := big.NewInt(3)
	// x3 := new(big.Int).Exp(x, &three, p)
	// y2 := new(big.Int).Sub(&x3, new(big.Int).Mul(&three, x))
	x3.Exp(x, &three, p)
	thriceX.Mul(&three, x)
	// y2.Sub(&x3, new(big.Int).Mul(&three, x))
	y2.Sub(&x3, &thriceX)
	y2.Add(&y2, ctx.Curve.Params().B)
	y2.Mod(&y2, p)
	return ctx.SquareRootModP(&y2)
}

// func (ctx *DHContext) HashToCurve_BF(s string, e *DHElement) {
// 	buf := []byte(s)
// 	p := ctx.Curve.Params().P
// 	count := 0
// 	for {
// 		// bufHash := Blake2b(buf)
// 		bufHash := BLAKE2B(buf, "HashToCurve")
// 		x := new(big.Int).SetBytes(bufHash)
// 		x = x.Mod(x, p)
// 		y := ctx.YfromX(x)
// 		if ctx.Curve.IsOnCurve(x, y) {
// 			e.x, e.y = x, y
// 			// fmt.Println("count", count)
// 			return
// 			// return DHElement{x, y}
// 		}
// 		count += 1
// 		buf = bufHash
// 		// buf = Blake2b(bufHash)
// 	}
// }

func (ctx *DHContext) RandomScalar() *big.Int {
	ret := frand.BigIntn(ctx.Curve.Params().P)
	// ret, err := crand.Int(crand.Reader, ctx.Curve.Params().P)
	// Panic(err)
	return ret
}

func (ctx *DHContext) RandomElement(ret *DHElement) {
	ctx.EC_BaseMultiply(ctx.RandomScalar(), ret)
}

func (ctx *DHContext) RandomElements(n int) []DHElement {
	ret := make([]DHElement, n)
	for i := 0; i < n; i++ {
		ctx.EC_BaseMultiply(ctx.RandomScalar(), &ret[i])
	}
	return ret
}

// #############################################################################

func (p *DHElement) String() string {
	return p.x.Text(16) + "," + p.y.Text(16)
}

func (p *DHElement) Serialize() []byte {
	ret := p.x.Bytes()
	ret = append(make([]byte, 32-len(ret)), ret...) // Pad to 32 bytes
	var sign big.Int

	// sign := new(big.Int).Mod(p.y, &two).Int64() + 2
	return append(ret, byte(sign.Mod(p.y, &two).Int64()+2))
}

func DHElementFromBytes(ctx *DHContext, b []byte) DHElement {
	Assert(len(b) == 33)
	var x, temp big.Int

	// x := new(big.Int).SetBytes(b[:32])
	x.SetBytes(b[:32])
	y := ctx.YfromX(&x)

	parity := temp.Mod(y, &two).Int64()

	if int64(b[32])-2 != parity {
		y.Sub(ctx.Curve.Params().P, y)
	}
	return DHElement{&x, y}
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
