package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"math"
	"math/big"
)

/* -------------------------------------------------------------------------- */

var zero big.Int = *new(big.Int).SetInt64(0)
var one big.Int = *new(big.Int).SetInt64(1)
var two big.Int = *new(big.Int).SetInt64(2)
var three big.Int = *new(big.Int).SetInt64(3)
var four big.Int = *new(big.Int).SetInt64(4)

/* -------------------------------------------------------------------------- */

type HashFunction func([]byte) []byte

type HtoCParams struct {
	A, B, q, Z *big.Int
	DST        string
	k, m, L, h int
	H          HashFunction
	b, s       int
}

func NewHtoCParams(suite string) (*HtoCParams, error) {
	var A, B, q, Z *big.Int
	var DST string
	var k, m, L, h, b, s int
	var ok bool
	var H HashFunction

	switch suite {
	case "P256_XMD:SHA-256_SSWU_RO_":
		A = new(big.Int).SetInt64(-3)
		B, ok = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
		Assert(ok)
		q, ok = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
		Assert(ok)
		Z = new(big.Int).SetInt64(-10)
		DST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
		k = 128
		m = 1
		h = 1
		H = SHA256
		b = 32
		s = 64
	case "P384_XMD:SHA-384_SSWU_RO_":
		A = new(big.Int).SetInt64(-3)
		B, ok = new(big.Int).SetString("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
		Assert(ok)
		q, ok = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
		Assert(ok)
		Z = new(big.Int).SetInt64(-12)
		DST = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_"
		k = 192
		m = 1
		h = 1
		H = SHA384
		b = 48
		s = 128
	case "P521_XMD:SHA-512_SSWU_RO_":
		A = new(big.Int).SetInt64(-3)
		B, ok = new(big.Int).SetString("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16)
		Assert(ok)
		q, ok = new(big.Int).SetString("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
		Assert(ok)
		Z = new(big.Int).SetInt64(-4)
		DST = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_"
		k = 256
		m = 1
		h = 1
		H = SHA512
		b = 64
		s = 128
	}

	L = int(math.Ceil(float64(q.BitLen()+k) / 8)) // expansion size in bytes
	return &HtoCParams{A, B, q, Z, DST, k, m, L, h, H, b, s}, nil
}

/* -------------------------------------------------------------------------- */

func CMOV(a, b interface{}, c bool) interface{} {
	if c {
		return b
	}
	return a
}

// big endian
func I2OSP(val *big.Int, length int) []byte {
	Assert(val.BitLen() <= length*8)
	ret := val.Bytes()
	padLen := length - len(ret)
	return append(make([]byte, padLen), ret...)
}

func I2OSP_int(val int, length int) []byte {
	var v big.Int
	v.SetUint64(uint64(val))
	return I2OSP(&v, length)
}

func Inv0(x, p *big.Int) *big.Int {
	var r, two big.Int
	two.SetInt64(2)
	return r.Exp(x, r.Sub(p, &two), p)
}

func IsSquare(x, p *big.Int) bool {
	var r, exp big.Int
	exp.Div(exp.Sub(p, &one), &two)
	r.Exp(x, &exp, p)

	return (r.Cmp(exp.SetUint64(0)) == 0) || (r.Cmp(exp.SetUint64(1)) == 0)
}

// big endian
func OS2IP(octets []byte) *big.Int {
	var ret big.Int
	return ret.SetBytes(octets)
	// return new(big.Int).SetBytes(octets)
}

func Sgn0(x, p *big.Int) int {
	var r big.Int
	x.Mod(x, p)

	return int(r.Mod(x, &two).Int64())
}

func SHA256(msg []byte) []byte {
	ret := sha256.Sum256([]byte(msg))
	return ret[:]
}

func SHA384(msg []byte) []byte {
	ret := sha512.Sum384([]byte(msg))
	return ret[:]
}

func SHA512(msg []byte) []byte {
	ret := sha512.Sum512([]byte(msg))
	return ret[:]
}

func Sqrt(x, p *big.Int) *big.Int {
	var p1, exp, ret big.Int
	p1.Add(p, &one)
	exp.Div(&p1, &four)
	return ret.Exp(x, &exp, p)
	// return new(big.Int).Exp(x, &exp, p)
}

func (params *HtoCParams) SqrtRatio3Mod4(u, v *big.Int) (bool, big.Int) {
	var c1, c2, tv1, tv2, tv3, y1, y2, y big.Int
	c1.Div(c1.Sub(params.q, &three), &four)
	c2.Set(Sqrt(c2.Neg(params.Z), params.q))

	//    1. tv1 = v^2
	tv1.Exp(v, &two, params.q)
	//    2. tv2 = u * v
	tv2.Mul(u, v)
	//    3. tv1 = tv1 * tv2
	tv1.Mul(&tv1, &tv2)
	//    4. y1 = tv1^c1
	y1.Exp(&tv1, &c1, params.q)
	//    5. y1 = y1 * tv2
	y1.Mul(&y1, &tv2)
	//    6. y2 = y1 * c2
	y2.Mul(&y1, &c2)
	//    7. tv3 = y1^2
	tv3.Exp(&y1, &two, params.q)
	//    8. tv3 = tv3 * v
	tv3.Mul(&tv3, v)
	//    9. isQR = tv3 == u
	tv3.Mod(&tv3, params.q)
	u.Mod(u, params.q)
	isQR := (tv3.Cmp(u) == 0)
	//    10. y = CMOV(y2, y1, isQR)
	y = CMOV(y2, y1, isQR).(big.Int)
	//    11. return (isQR, y)
	return isQR, y
}

func XOR(a, b []byte) []byte {
	Assert(len(a) == len(b))
	ret := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		ret[i] = (a[i] ^ b[i])
	}
	return ret
}

/* -------------------------------------------------------------------------- */

// From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.3

func (params *HtoCParams) HashToField(msg string, count int) []big.Int {
	len_in_bytes := count * params.m * params.L
	uniform_bytes := params.ExpandMessageXMD(msg, params.DST, len_in_bytes)
	u := make([]big.Int, count)
	for i := 0; i < count; i++ {
		elm_offset := params.L * i
		u[i].Mod(OS2IP(uniform_bytes[elm_offset:elm_offset+params.L]), params.q)
	}
	return u
}

func (params *HtoCParams) ExpandMessageXMD(msg, DST string, len_in_bytes int) []byte {
	// 1. ell = ceil(len_in_bytes / b_in_bytes)
	ell := math.Ceil(float64(len_in_bytes) / float64(params.b))
	// 2.  ABORT if ell > 255
	Assert(ell <= 255)
	// 3.  DST_prime = DST || I2OSP(len(DST), 1)
	DST_prime := DST + string(I2OSP_int(len(DST), 1))
	// 4.  Z_pad = I2OSP(0, s_in_bytes)
	Z_pad := string(I2OSP_int(0, params.s))
	// 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
	l_i_b_str := string(I2OSP_int(len_in_bytes, 2))
	// 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
	msg_prime := Z_pad + msg + l_i_b_str + string(I2OSP_int(0, 1)) + DST_prime
	b := make([][]byte, int(ell+1))
	// 7.  b_0 = H(msg_prime)
	b[0] = params.H([]byte(msg_prime))
	// 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	b[1] = params.H([]byte(string(b[0]) + string(I2OSP_int(1, 1)) + DST_prime))
	uniform_bytes := string(b[1])
	// 9.  for i in (2, ..., ell):
	for i := 2; i < len(b); i++ {
		// 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		b[i] = params.H([]byte(string(XOR(b[0], b[i-1])) + string(I2OSP_int(i, 1)) + DST_prime))
		// 11. uniform_bytes = b_1 || ... || b_ell
		uniform_bytes += string(b[i])
	}
	// 12. return substr(uniform_bytes, 0, len_in_bytes)
	return []byte(uniform_bytes[0:len_in_bytes])
}

func (params *HtoCParams) MapToCurveSWUStraight(u *big.Int) DHElement {
	var tv1, tv2, tv3, tv4, tv5, tv6, x, y, negY big.Int
	//  1.  tv1 = u^2
	tv1.Exp(u, &two, params.q)
	//  2.  tv1 = Z * tv1
	tv1.Mul(params.Z, &tv1)
	//  3.  tv2 = tv1^2
	tv2.Exp(&tv1, &two, params.q)
	//  4.  tv2 = tv2 + tv1
	tv2.Add(&tv2, &tv1)
	//  5.  tv3 = tv2 + 1
	tv3.Add(&tv2, &one)
	//  6.  tv3 = B * tv3
	tv3.Mul(params.B, &tv3)
	//  7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv2.Mod(&tv2, params.q)
	tv4 = CMOV(params.Z, *tv4.Neg(&tv2), tv2.Cmp(&zero) != 0).(big.Int)
	//  8.  tv4 = A * tv4
	tv4.Mul(params.A, &tv4)
	//  9.  tv2 = tv3^2
	tv2.Exp(&tv3, &two, params.q)
	//  10. tv6 = tv4^2
	tv6.Exp(&tv4, &two, params.q)
	//  11. tv5 = A * tv6
	tv5.Mul(params.A, &tv6)
	//  12. tv2 = tv2 + tv5
	tv2.Add(&tv2, &tv5)
	//  13. tv2 = tv2 * tv3
	tv2.Mul(&tv2, &tv3)
	//  14. tv6 = tv6 * tv4
	tv6.Mul(&tv6, &tv4)
	//  15. tv5 = B * tv6
	tv5.Mul(params.B, &tv6)
	//  16. tv2 = tv2 + tv5
	tv2.Add(&tv2, &tv5)
	//  17.   x = tv1 * tv3
	x.Mul(&tv1, &tv3)
	//  18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	is_gx1_square, y1 := params.SqrtRatio3Mod4(&tv2, &tv6)
	//  19.   y = tv1 * u
	y.Mul(&tv1, u)
	//  20.   y = y * y1
	y.Mul(&y, &y1)
	//  21.   x = CMOV(x, tv3, is_gx1_square)
	x = CMOV(x, tv3, is_gx1_square).(big.Int)
	//  22.   y = CMOV(y, y1, is_gx1_square)
	y = CMOV(y, y1, is_gx1_square).(big.Int)
	//  23.  e1 = sgn0(u) == sgn0(y)
	e1 := (Sgn0(u, params.q) == Sgn0(&y, params.q))
	//  24.   y = CMOV(-y, y, e1)
	negY.Neg(&y)
	y = CMOV(negY, y, e1).(big.Int)
	// y = CMOV(*new(big.Int).Neg(&y), y, e1).(big.Int)
	//  25.   x = x / tv4
	x.Mul(&x, tv4.ModInverse(&tv4, params.q))
	//  26. return (x, y)
	x.Mod(&x, params.q)
	y.Mod(&y, params.q)
	return DHElement{&x, &y}
}

func (params *HtoCParams) ClearCofactor(R DHElement) DHElement {
	if params.h == 1 {
		return R
	} else {
		return DHElement{}
	}
}

// from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-3
func HashToCurve_13(msg string, P *DHElement, curve elliptic.Curve, params *HtoCParams) {
	u := params.HashToField(msg, 2)

	Q0 := params.MapToCurveSWUStraight(&u[0])
	Q1 := params.MapToCurveSWUStraight(&u[1])

	Assert(curve.IsOnCurve(Q0.x, Q0.y))
	Assert(curve.IsOnCurve(Q1.x, Q1.y))

	Px, Py := curve.Add(Q0.x, Q0.y, Q1.x, Q1.y)
	*P = params.ClearCofactor(DHElement{Px, Py})
}
