package main

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	// "golang.org/x/crypto/sha3"
)

func CMOV(a, b interface{}, c bool) interface{} {
	if c {
		return b
	}
	return a
}

// func Concat(a, b []byte) []byte {
// 	return append(a, b...)
// }

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
	var r, exp, one, two big.Int
	two.SetInt64(2)
	one.SetInt64(1)

	// fmt.Println("two", two.Text(16))
	// fmt.Println("p", p.Text(16))
	exp.Div(exp.Sub(p, &one), &two)
	// exp.Sub(p, exp.SetInt64(1))
	// fmt.Println("(p-1)/2", exp.Text(16))
	r.Exp(x, &exp, p)

	return (r.Cmp(exp.SetUint64(0)) == 0) || (r.Cmp(exp.SetUint64(1)) == 0)
}

// big endian
func OS2IP(octets []byte) *big.Int {
	// fmt.Println(new(big.Int).SetBytes(octets).Text(16))
	return new(big.Int).SetBytes(octets)
}

func Sgn0(x, p *big.Int) int {
	var r, two big.Int
	two.SetInt64(2)
	x.Mod(x, p)

	return int(r.Mod(x, &two).Int64())
}

func SHA256(msg []byte) []byte {
	ret := sha256.Sum256([]byte(msg))
	return ret[:]
}

func Sqrt(x, p *big.Int) *big.Int {
	var one, four, p1, exp big.Int
	one.SetInt64(1)
	four.SetInt64(4)
	p1.Add(p, &one)
	exp.Div(&p1, &four)

	// fmt.Println("p1 ", p1.Text(16))
	// fmt.Println("exp", exp.Text(16))

	return new(big.Int).Exp(x, &exp, p)
}

func SqrtRatio(u, v big.Int, p *big.Int) (bool, big.Int) {
	var c1, c2, Z, tv1, tv2, tv3, y1, y2, y big.Int
	Z.SetInt64(-10)
	c1.Div(c1.Sub(p, c1.SetInt64(3)), c1.SetInt64(4))
	c2.Set(Sqrt(c2.Neg(&Z), p))

	//    1. tv1 = v^2
	tv1.Exp(&v, tv1.SetInt64(2), p)

	//    2. tv2 = u * v
	tv2.Mul(&u, &v)

	//    3. tv1 = tv1 * tv2
	tv1.Mul(&tv1, &tv2)

	//    4. y1 = tv1^c1
	y1.Exp(&tv1, &c1, p)

	//    5. y1 = y1 * tv2
	y1.Mul(&y1, &tv2)

	//    6. y2 = y1 * c2
	y2.Mul(&y1, &c2)

	//    7. tv3 = y1^2
	tv3.Exp(&y1, tv3.SetInt64(2), p)

	//    8. tv3 = tv3 * v
	tv3.Mul(&tv3, &v)

	//    9. isQR = tv3 == u
	tv3.Mod(&tv3, p)
	u.Mod(&u, p)
	isQR := (tv3.Cmp(&u) == 0)
	fmt.Println("isQR", isQR)

	//    10. y = CMOV(y2, y1, isQR)
	y = CMOV(y2, y1, isQR).(big.Int)

	//    11. return (isQR, y)
	// y.Mod(&y, p)
	return isQR, y
}

// func SqrtRatioSimple(u, v big.Int, p *big.Int) (bool, big.Int) {
// 	var r, Z big.Int
// 	Z.SetInt64(-10)

// 	r.Mul(&u, r.ModInverse(&v, p))
// 	if IsSquare(&r, p) {
// 		return true, *Sqrt(&r, p)
// 	} else {
// 		return false, *Sqrt(r.Mul(&r, &Z), p)
// 	}
// }

func XOR(a, b []byte) []byte {
	Assert(len(a) == len(b))
	ret := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		ret[i] = (a[i] ^ b[i])
	}
	return ret
}

/* -------------------------------------------------------------------------- */

// From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.4.2

// func ExpandMessageXOF(msg, DST string, len_in_bytes int) []byte {
// 	H := sha3.NewShake128()
// 	DST_prime := Concat([]byte(DST), I2OSP(big.NewInt(int64(len(DST))), 1))
// 	msg_prime := Concat(Concat([]byte(msg), I2OSP(big.NewInt(int64(len_in_bytes)), 2)), DST_prime)
// 	uniform_bytes := make([]byte, len_in_bytes)
// 	H.Write(msg_prime)
// 	H.Read(uniform_bytes)
// 	return uniform_bytes
// }

/* -------------------------------------------------------------------------- */

// From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.3

func HashToField(p *big.Int, msg string, count int) []big.Int {
	k := 128                                       // security level
	m := 1                                         // extension degee for P-256
	L := int(math.Ceil(float64(p.BitLen()+k) / 8)) // expansion size in bytes
	DST := "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"

	len_in_bytes := count * m * L
	uniform_bytes := ExpandMessageXMD(msg, DST, len_in_bytes)

	u := make([]big.Int, count)
	for i := 0; i < count; i++ {
		elm_offset := L * i
		u[i].Mod(OS2IP(uniform_bytes[elm_offset:elm_offset+L]), p)
	}
	return u
}

func ExpandMessageXMD(msg, DST string, len_in_bytes int) []byte {
	b_in_bytes := uint64(32)
	s_in_bytes := uint64(64)

	// 1. ell = ceil(len_in_bytes / b_in_bytes)
	ell := math.Ceil(float64(len_in_bytes) / float64(b_in_bytes))

	// 2.  ABORT if ell > 255
	Assert(ell <= 255)

	// 3.  DST_prime = DST || I2OSP(len(DST), 1)
	DST_prime := DST + string(I2OSP_int(len(DST), 1))

	// 4.  Z_pad = I2OSP(0, s_in_bytes)
	Z_pad := string(I2OSP_int(0, int(s_in_bytes)))

	// 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
	l_i_b_str := string(I2OSP_int(len_in_bytes, 2))

	// 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
	msg_prime := Z_pad + msg + l_i_b_str + string(I2OSP_int(0, 1)) + DST_prime

	b := make([][]byte, int(ell+1))
	// 7.  b_0 = H(msg_prime)
	b[0] = SHA256([]byte(msg_prime))

	// 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	b[1] = SHA256([]byte(string(b[0]) + string(I2OSP_int(1, 1)) + DST_prime))
	uniform_bytes := string(b[1])
	// 9.  for i in (2, ..., ell):
	for i := 2; i < len(b); i++ {
		// 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		b[i] = SHA256([]byte(string(XOR(b[0], b[i-1])) + string(I2OSP_int(i, 1)) + DST_prime))
		// 11. uniform_bytes = b_1 || ... || b_ell
		uniform_bytes += string(b[i])
	}

	// 12. return substr(uniform_bytes, 0, len_in_bytes)
	return []byte(uniform_bytes[0:len_in_bytes])
}

func MapToCurveSimpleSWU(p, u *big.Int) DHElement {
	var tv1, tv2, tv3, tv4, tv5, tv6, x, y, A, B, Z, zero big.Int

	zero.SetInt64(0)
	Z.SetInt64(-10)
	A.SetInt64(-3)
	B.SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

	//  1.  tv1 = u^2
	tv1.Exp(u, tv1.SetInt64(2), p)

	//  2.  tv1 = Z * tv1
	tv1.Mul(&Z, &tv1)

	//  3.  tv2 = tv1^2
	tv2.Exp(&tv1, tv2.SetInt64(2), p)

	//  4.  tv2 = tv2 + tv1
	tv2.Add(&tv2, &tv1)

	//  5.  tv3 = tv2 + 1
	tv3.Add(&tv2, tv3.SetInt64(1))

	//  6.  tv3 = B * tv3
	tv3.Mul(&B, &tv3)

	//  7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv2.Mod(&tv2, p)
	tv4 = CMOV(Z, *tv4.Neg(&tv2), tv2.Cmp(&zero) != 0).(big.Int)

	//  8.  tv4 = A * tv4
	tv4.Mul(&A, &tv4)

	//  9.  tv2 = tv3^2
	tv2.Exp(&tv3, tv2.SetInt64(2), p)

	//  10. tv6 = tv4^2
	tv6.Exp(&tv4, tv6.SetInt64(2), p)

	//  11. tv5 = A * tv6
	tv5.Mul(&A, &tv6)

	//  12. tv2 = tv2 + tv5
	tv2.Add(&tv2, &tv5)

	//  13. tv2 = tv2 * tv3
	tv2.Mul(&tv2, &tv3)

	//  14. tv6 = tv6 * tv4
	tv6.Mul(&tv6, &tv4)

	//  15. tv5 = B * tv6
	tv5.Mul(&B, &tv6)

	//  16. tv2 = tv2 + tv5
	tv2.Add(&tv2, &tv5)

	//  17.   x = tv1 * tv3
	x.Mul(&tv1, &tv3)

	//  18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	is_gx1_square, y1 := SqrtRatio(tv2, tv6, p)
	// is_gx1_square, y1 := SqrtRatioSimple(tv2, tv6, p)
	// fmt.Println("is_gx1_square", is_gx1_square)

	//  19.   y = tv1 * u
	y.Mul(&tv1, u)

	//  20.   y = y * y1
	y.Mul(&y, &y1)

	//  21.   x = CMOV(x, tv3, is_gx1_square)
	x = CMOV(x, tv3, is_gx1_square).(big.Int)

	//  22.   y = CMOV(y, y1, is_gx1_square)
	y = CMOV(y, y1, is_gx1_square).(big.Int)
	// fmt.Println("tv3", y1.Text(16))
	// fmt.Println("y1", y1.Text(16))

	//  23.  e1 = sgn0(u) == sgn0(y)
	e1 := (Sgn0(u, p) == Sgn0(&y, p))
	// fmt.Println("e1", e1)

	//  24.   y = CMOV(-y, y, e1)
	y = CMOV(*new(big.Int).Neg(&y), y, e1).(big.Int)

	//  25.   x = x / tv4
	x.Mul(&x, tv4.ModInverse(&tv4, p))

	//  26. return (x, y)
	x.Mod(&x, p)
	y.Mod(&y, p)
	return DHElement{&x, &y}
}

func MapToCurveSWU(p, u *big.Int) DHElement {
	var zero, one, two, three, four, Z, A, B big.Int

	// p := ctx.Curve.Params().P
	zero.SetInt64(0)
	one.SetInt64(1)
	two.SetInt64(2)
	three.SetInt64(3)
	four.SetInt64(4)
	// 115792089210356248762697446949407573530086143415290314195533631308867097853941
	// Z.SetString("ffffffff00000001000000000000000000000000fffffffffffffffffffffff5", 16)
	Z.SetInt64(-10)
	Z.Mod(&Z, p)
	// A.SetString("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
	A.SetInt64(-3)
	A.Mod(&A, p)
	B.SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	// fmt.Println("A", A.Text(16))
	// fmt.Println("B", B.Text(16))
	// fmt.Println("Z", Z.Text(16))

	var arg, tv1, x1, gx1, x2, gx2, x, y big.Int
	var z2, u4, u2, z2u4, zu2 big.Int

	z2.Exp(&Z, &two, p)
	u2.Exp(u, &two, p)
	u4.Exp(u, &four, p)
	z2u4.Mul(&z2, &u4)
	zu2.Mul(&Z, &u2)

	// 1. tv1 = inv0(Z^2 * u^4 + Z * u^2) mod p
	arg.Add(&z2u4, &zu2)
	tv1 = *Inv0(&arg, p)
	tv1.Mod(&tv1, p)

	var negB, Ainv, negBAinv, tv1one big.Int
	negB.Neg(&B)
	Ainv.ModInverse(&A, p)
	negBAinv.Mul(&negB, &Ainv)
	tv1one.Add(&one, &tv1)

	// fmt.Println("negB", negB.Text(16))
	// fmt.Println("Ainv", Ainv.Text(16))
	// fmt.Println("negBAinv", negBAinv.Text(16))
	// fmt.Println("tv1one", tv1one.Text(16))

	// 2.  x1 = (-B / A) * (1 + tv1) mod p
	x1.Mul(&negBAinv, &tv1one)
	x1.Mod(&x1, p)
	// fmt.Println("x1", x1.Text(16))

	var za, zaInv big.Int
	za.Mul(&Z, &A)
	zaInv.ModInverse(&za, p)

	// 3.  If tv1 == 0, set x1 = B / (Z * A) mod p
	if tv1.Cmp(&zero) == 0 {
		// fmt.Println("tv1.Cmp(&zero) == 0")
		x1.Mul(&B, &zaInv)
	}

	var x13, Ax1 big.Int
	x13.Exp(&x1, &three, p)
	Ax1.Mul(&A, &x1)

	// 4. gx1 = x1^3 + A * x1 + B mod p
	gx1.Add(new(big.Int).Add(&x13, &Ax1), &B)

	// 5. x2 = Z * u^2 * x1 mod p
	x2.Mul(new(big.Int).Mul(&Z, new(big.Int).Exp(u, &two, p)), &x1)

	// 6. gx2 = x2^3 + A * x2 + B mod p
	gx2.Add(new(big.Int).Add(new(big.Int).Exp(&x2, &three, p), new(big.Int).Mul(&A, &x2)), &B)

	gx1.Mod(&gx1, p)
	gx2.Mod(&gx2, p)
	// 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
	if IsSquare(&gx1, p) {
		// fmt.Println("IsSquare(&gx1, p)")
		x = x1
		y = *Sqrt(&gx1, p)
		// fmt.Println("x", x.Text(16))
		// fmt.Println("y", y.Text(16))
	} else {
		// 8.  Else set x = x2 and y = sqrt(gx2)
		x = x2
		// fmt.Println("IsSquare(&gx2, p)")
		y = *Sqrt(&gx2, p)
	}

	// 9.  If sgn0(u) != sgn0(y), set y = -y
	if Sgn0(u, p) != Sgn0(&y, p) {
		// fmt.Println("Sgn0(u, p) != Sgn0(&y, p)")
		y.Neg(&y)
	}

	// 10. return (x, y)
	x.Mod(&x, p)
	y.Mod(&y, p)
	return DHElement{&x, &y}
}

func ClearCofactor(R DHElement) DHElement {
	// Not needed for P-256 as cofactor h = 1
	return R
}

// from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-3
func (ctx *DHContext) HashToCurve_13(msg string, P *DHElement) {
	// ctx.HashToCurve(msg, P)

	p := ctx.Curve.Params().P
	u := HashToField(p, msg, 2)
	// fmt.Println("u[0]", u[0].Text(16))
	// fmt.Println("u[1]", u[1].Text(16))
	Q0 := MapToCurveSWU(p, &u[0])
	Q1 := MapToCurveSWU(p, &u[1])

	// Q0 := MapToCurveSimpleSWU(p, &u[0])
	// Q1 := MapToCurveSimpleSWU(p, &u[1])

	// fmt.Println("Q0.x", Q0.x.Text(16))
	// fmt.Println("Q0.y", Q0.y.Text(16))
	// fmt.Println("Q1.x", Q1.x.Text(16))
	// fmt.Println("Q1.y", Q1.y.Text(16))

	Assert(ctx.Curve.IsOnCurve(Q0.x, Q0.y))
	Assert(ctx.Curve.IsOnCurve(Q1.x, Q1.y))

	ctx.EC_Add(Q0, Q1, P)
	*P = ClearCofactor(*P)
}
