package main

import (
	"crypto/elliptic"
	"math/big"
)

func zForAffine(x, y, z *big.Int) *big.Int {
	// z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

func Add(x1, y1, x2, y2, retX, retY *big.Int, curve *elliptic.CurveParams) {
	var x, y, z, z1, z2 big.Int
	// z1 := zForAffine(x1, y1)
	// z2 := zForAffine(x2, y2)
	zForAffine(x1, y1, &z1)
	zForAffine(x2, y2, &z2)
	// x, y, z := addJacobian(x1, y1, &z1, x2, y2, &z2, curve)
	addJacobian(x1, y1, &z1, x2, y2, &z2, &x, &y, &z, curve)
	affineFromJacobian(&x, &y, &z, retX, retY, curve)
}

func affineFromJacobian(x, y, z, xOut, yOut *big.Int, curve *elliptic.CurveParams) {
	// var xOut, yOut big.Int
	if z.Sign() == 0 {
		// return new(big.Int), new(big.Int)
		// return &xOut, &yOut
		return
	}

	var zinv, zinvsq big.Int

	// zinv := new(big.Int).ModInverse(z, curve.P)
	zinv.ModInverse(z, curve.P)
	// zinvsq := new(big.Int).Mul(zinv, zinv)
	zinvsq.Mul(&zinv, &zinv)

	// xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mul(x, &zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(&zinvsq, &zinv)

	// yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mul(y, &zinvsq)
	yOut.Mod(yOut, curve.P)
	// return &xOut, &yOut
}

func addJacobian(x1, y1, z1, x2, y2, z2, x3, y3, z3 *big.Int, curve *elliptic.CurveParams) {
	// (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	// x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	// var x3, y3, z3 big.Int

	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		// return &x3, &y3, &z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		// return &x3, &y3, &z3
	}

	var z1z1, z2z2 big.Int
	// z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mul(z1, z1)
	z1z1.Mod(&z1z1, curve.P)
	// z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mul(z2, z2)
	z2z2.Mod(&z2z2, curve.P)

	var u1, u2, h, i, j, s1, s2, r, v big.Int

	// u1 := new(big.Int).Mul(x1, &z2z2)
	u1.Mul(x1, &z2z2)
	u1.Mod(&u1, curve.P)
	// u2 := new(big.Int).Mul(x2, &z1z1)
	u2.Mul(x2, &z1z1)
	u2.Mod(&u2, curve.P)
	// h := new(big.Int).Sub(&u2, &u1)
	h.Sub(&u2, &u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(&h, curve.P)
	}

	// i := new(big.Int).Lsh(h, 1)
	i.Lsh(&h, 1)
	i.Mul(&i, &i)
	// j := new(big.Int).Mul(h, i)
	j.Mul(&h, &i)

	// s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(y1, z2)
	s1.Mul(&s1, &z2z2)
	s1.Mod(&s1, curve.P)
	// s2 := new(big.Int).Mul(y2, z1)

	s2.Mul(y2, z1)
	s2.Mul(&s2, &z1z1)
	s2.Mod(&s2, curve.P)
	// r := new(big.Int).Sub(&s2, &s1)
	r.Sub(&s2, &s1)
	if r.Sign() == -1 {
		r.Add(&r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		doubleJacobian(x1, y1, z1, x3, y3, z3, curve)
	}
	r.Lsh(&r, 1)
	// v := new(big.Int).Mul(&u1, &i)
	v.Mul(&u1, &i)

	x3.Set(&r)
	x3.Mul(x3, x3)
	x3.Sub(x3, &j)
	x3.Sub(x3, &v)
	x3.Sub(x3, &v)
	x3.Mod(x3, curve.P)

	y3.Set(&r)
	v.Sub(&v, x3)
	y3.Mul(y3, &v)
	s1.Mul(&s1, &j)
	s1.Lsh(&s1, 1)
	y3.Sub(y3, &s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, &z1z1)
	z3.Sub(z3, &z2z2)
	z3.Mul(z3, &h)
	z3.Mod(z3, curve.P)

	// return &x3, &y3, &z3
}

func doubleJacobian(x, y, z, x3, y3, z3 *big.Int, curve *elliptic.CurveParams) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
	var delta, gamma, alpha, alpha2 big.Int

	// delta := new(big.Int).Mul(z, z)
	delta.Mul(z, z)
	delta.Mod(&delta, curve.P)
	// gamma := new(big.Int).Mul(y, y)
	delta.Mul(y, y)
	gamma.Mod(&gamma, curve.P)
	// alpha := new(big.Int).Sub(x, delta)
	alpha.Sub(x, &delta)
	if alpha.Sign() == -1 {
		alpha.Add(&alpha, curve.P)
	}
	// alpha2 := new(big.Int).Add(x, delta)
	alpha2.Add(x, &delta)
	alpha.Mul(&alpha, &alpha2)
	alpha2.Set(&alpha)
	alpha.Lsh(&alpha, 1)
	alpha.Add(&alpha, &alpha2)

	beta := alpha2.Mul(x, &gamma)

	// var x3, beta8, z3 big.Int
	var beta8 big.Int
	// x3 := new(big.Int).Mul(alpha, alpha)
	x3.Mul(&alpha, &alpha)

	// beta8 := new(big.Int).Lsh(beta, 3)
	beta8.Lsh(beta, 3)
	beta8.Mod(&beta8, curve.P)

	x3.Sub(x3, &beta8)
	if x3.Sign() == -1 {
		x3.Add(x3, curve.P)
	}
	x3.Mod(x3, curve.P)

	// z3 := new(big.Int).Add(y, z)
	z3.Add(y, z)
	z3.Mul(z3, z3)
	z3.Sub(z3, &gamma)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Sub(z3, &delta)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Mod(z3, curve.P)

	beta.Lsh(beta, 2)
	beta.Sub(beta, x3)
	if beta.Sign() == -1 {
		beta.Add(beta, curve.P)
	}
	*y3 = *alpha.Mul(&alpha, beta)

	gamma.Mul(&gamma, &gamma)
	gamma.Lsh(&gamma, 3)
	gamma.Mod(&gamma, curve.P)

	y3.Sub(y3, &gamma)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mod(y3, curve.P)

	// return &x3, y3, &z3
}
