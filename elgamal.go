package main

import (
	crand "crypto/rand"
	"fmt"
	"math"
	"math/big"
)

func NewEGContext(ret *EGContext, numModuli, maxBits uint) {
	NewDHContext(&ret.ecc)
	bitSize := uint(math.Ceil(float64(maxBits) / float64(numModuli)))

	ret.nModuli = numModuli
	ret.N = new(big.Int)
	ret.n = make([]*big.Int, numModuli)
	ret.Ny = make([]*big.Int, numModuli)

	fmt.Println("Bitsize:", bitSize+1)

	ret.genModuli(bitSize + 1)
	fmt.Print("Moduli: ")
	for i := 0; i < int(numModuli); i++ {
		fmt.Print(ret.n[i].Text(10), " ")
	}
	fmt.Println("")
	fmt.Println("N:", ret.N.Text(10))

	ret.genTable(12) // Works for up to 32-bit sums
}

func (ctx *EGContext) genModuli(bitSize uint) {
	var gcd big.Int
	var err error

	i := 0
	ctx.N.SetInt64(1)
	for i < int(ctx.nModuli) {
		// ctx.n[i], err = crand.Int(crand.Reader, new(big.Int).Lsh(&one, bitSize))
		ctx.n[i], err = crand.Prime(crand.Reader, int(bitSize))
		Check(err)
		coPrime := true
		for j := 0; j < i; j++ {
			gcd.GCD(nil, nil, ctx.n[i], ctx.n[j])
			// Assert(gcd.Cmp(&one) == 0)
			if gcd.Cmp(&one) != 0 {
				coPrime = false
			}
		}
		if coPrime {
			ctx.N.Mul(ctx.N, ctx.n[i])
			i += 1
		}
	}

	var y big.Int
	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.Ny[i] = new(big.Int).Div(ctx.N, ctx.n[i])
		y.ModInverse(ctx.Ny[i], ctx.n[i])
		ctx.Ny[i].Mul(ctx.Ny[i], &y)
	}
}

func (ctx *EGContext) genTable(bitSize uint) {
	maxV := 1 << (bitSize + 1)
	fmt.Println("maxV:", maxV)

	var val DHElement
	ctx.table = make(map[string]big.Int)
	for i := 0; i < maxV; i++ {
		bigI := big.NewInt(int64(i))
		ctx.ecc.EC_BaseMultiply(bigI, &val)
		ctx.table[string(val.Serialize())] = *bigI
	}
}

func (ctx *EGContext) BSGS(beta *DHElement) *big.Int {
	var GminusM, gamma DHElement
	m := int64(len(ctx.table))

	ctx.ecc.EC_BaseMultiply(big.NewInt(m), &GminusM)
	ctx.ecc.EC_Negate(&GminusM)

	gamma.x = new(big.Int).Set(beta.x)
	gamma.y = new(big.Int).Set(beta.y)

	for i := int64(0); i < m; i++ {
		j, ok := ctx.lookup(string(gamma.Serialize()))
		if ok {
			return new(big.Int).Add(&j, big.NewInt(i*m))
		}
		ctx.ecc.EC_Add(gamma, GminusM, &gamma)
		fmt.Println("Giant step")
	}

	return nil
}

// #############################################################################

func (ctx *EGContext) decrypt(sk DHScalar, c1, c2, Pm *DHElement) {
	var cPrime DHElement
	ctx.ecc.EC_Multiply(sk, *c1, &cPrime)
	ctx.ecc.EC_Negate(&cPrime)
	ctx.ecc.EC_Add(cPrime, *c2, Pm)
}

// func (ctx *EGContext) decryptCheck(sk DHScalar, c1, c2, Gm *DHElement) bool {
// 	var GmPrime DHElement
// 	ctx.decrypt(sk, c1, c2, &GmPrime)
// 	return GmPrime.String() == Gm.String()
// }

func (ctx *EGContext) encryptZero(pk, c1, c2 *DHElement) {
	k := ctx.ecc.RandomScalar()
	ctx.ecc.EC_BaseMultiply(k, c1)
	ctx.ecc.EC_Multiply(k, *pk, c2)
}

func (ctx *EGContext) encrypt(pk, c1, c2 *DHElement, m *big.Int) {
	ctx.encryptZero(pk, c1, c2)
	var Gm DHElement
	ctx.ecc.EC_BaseMultiply(m, &Gm)
	ctx.ecc.EC_Add(*c2, Gm, c2)
}

func (ctx *EGContext) add(a1, a2, b1, b2, ret1, ret2 *DHElement) {
	ctx.ecc.EC_Add(*a1, *b1, ret1)
	ctx.ecc.EC_Add(*a2, *b2, ret2)
}

func (ctx *EGContext) mapToInt(Pm []DHElement, m *big.Int) {
	m.Set(&zero)
	var term big.Int

	for i := 0; i < int(ctx.nModuli); i++ {
		// a := ctx.lookup_mod(string(Pm[i].Serialize()), ctx.n[i])
		// a, ok := ctx.lookup(string(Pm[i].Serialize()))
		a := ctx.BSGS(&Pm[i])
		Assert(a != nil)
		// Assert(ok)
		// fmt.Print(i, " ~ ", a.Text(10), " ")
		term.Mul(a, ctx.Ny[i])
		term.Mod(&term, ctx.N)
		m.Add(m, &term)
	}
	m.Mod(m, ctx.N)
	// fmt.Println("")
}

// func (ctx *EGContext) lookup_mod(s string, mod *big.Int) big.Int {
// 	for {
// 		a, ok := ctx.lookup(s)
// 	}
// }

func (ctx *EGContext) lookup(s string) (big.Int, bool) {
	a, ok := ctx.table[s]
	// Assert(ok)
	return a, ok
}

// #############################################################################

func (ctx *EGContext) EG_PubKey(sk DHScalar, pk *DHElement) {
	ctx.ecc.EC_BaseMultiply(sk, pk)
}

func (ctx *EGContext) EG_Encrypt(pk *DHElement, m *big.Int, ct *EGCiphertext) {
	var rem big.Int
	ct.c1 = make([]DHElement, ctx.nModuli)
	ct.c2 = make([]DHElement, ctx.nModuli)
	for i := 0; i < int(ctx.nModuli); i++ {
		rem.Mod(m, ctx.n[i])
		ctx.encrypt(pk, &ct.c1[i], &ct.c2[i], &rem)
	}
}

func (ctx *EGContext) EG_Decrypt(sk DHScalar, m *big.Int, ct *EGCiphertext) {
	Pm := make([]DHElement, ctx.nModuli)
	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.decrypt(sk, &ct.c1[i], &ct.c2[i], &Pm[i])
	}
	ctx.mapToInt(Pm, m)
}

// Adds b to a inplace
func (ctx *EGContext) EG_AddInplace(a *EGCiphertext, b *EGCiphertext) {
	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.add(&a.c1[i], &a.c2[i], &b.c1[i], &b.c2[i], &a.c1[i], &a.c2[i])
	}
}

func (ctx *EGContext) EG_Add(a, b, ret *EGCiphertext) {
	ret.c1 = make([]DHElement, ctx.nModuli)
	ret.c2 = make([]DHElement, ctx.nModuli)
	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.add(&a.c1[i], &a.c2[i], &b.c1[i], &b.c2[i], &ret.c1[i], &ret.c2[i])
	}
}

func (ctx *EGContext) EG_Rerandomize(pk *DHElement, ct *EGCiphertext) {
	var c1, c2 DHElement

	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.encryptZero(pk, &c1, &c2)
		ctx.add(&ct.c1[i], &ct.c2[i], &c1, &c2, &ct.c1[i], &ct.c2[i])
	}
}

func (ctx *EGContext) EG_RandomCt(pk *DHElement, ct *EGCiphertext) {
	ct.c1 = make([]DHElement, ctx.nModuli)
	ct.c2 = make([]DHElement, ctx.nModuli)
	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.encryptZero(pk, &ct.c1[i], &ct.c2[i])

		// 	ctx.ecc.RandomElement(&ct.c1[i])
		// 	ctx.ecc.RandomElement(&ct.c2[i])
	}
	// m := big.NewInt(0)
	// ctx.EG_Encrypt(pk, m, ct)

	// ct.c1 = ctx.ecc.RandomElements(int(ctx.nModuli))
	// ct.c2 = ctx.ecc.RandomElements(int(ctx.nModuli))
}

func (ctx *EGContext) EG_Serialize(ct *EGCiphertext) []byte {
	var ret []byte

	for i := 0; i < int(ctx.nModuli); i++ {
		ret = append(ret, ct.c1[i].Serialize()...)
		ret = append(ret, ct.c2[i].Serialize()...)
	}
	return ret
}

func (ctx *EGContext) EG_Deserialize(ctBytes []byte) EGCiphertext {
	Assert(len(ctBytes) == int(66*ctx.nModuli))
	var ct EGCiphertext
	ct.c1 = make([]DHElement, ctx.nModuli)
	ct.c2 = make([]DHElement, ctx.nModuli)

	for i := 0; i < int(ctx.nModuli); i++ {
		start := i * 66
		ct.c1[i] = DHElementFromBytes(&ctx.ecc, ctBytes[start:start+33])
		ct.c2[i] = DHElementFromBytes(&ctx.ecc, ctBytes[start+33:start+66])
	}
	return ct
}

// #############################################################################

func (ctx *EGContext) EGMP_PubKey(sk DHScalar, pk *DHElement) {
	ctx.EG_PubKey(sk, pk)
}

func (ctx *EGContext) EGMP_AggPubKey(pk []DHElement, apk *DHElement) {
	apk.x, apk.y = pk[0].x, pk[0].y
	for i := 1; i < len(pk); i++ {
		ctx.ecc.EC_Add(*apk, pk[i], apk)
	}
}

func (ctx *EGContext) EGMP_Decrypt(sk DHScalar, ct *EGCiphertext) []DHElement {
	cPrime := make([]DHElement, ctx.nModuli)
	for i := 0; i < int(ctx.nModuli); i++ {
		ctx.ecc.EC_Multiply(sk, ct.c1[i], &cPrime[i])
	}
	return cPrime
}

func (ctx *EGContext) EGMP_AggDecrypt(cPrime [][]DHElement, m *big.Int, ct *EGCiphertext) {
	Pm := make([]DHElement, ctx.nModuli)
	for j := 0; j < int(ctx.nModuli); j++ {
		ctx.ecc.EC_Negate(&cPrime[0][j])
		ctx.ecc.EC_Add(cPrime[0][j], ct.c2[j], &Pm[j])
	}

	for i := 1; i < len(cPrime); i++ {
		for j := 0; j < int(ctx.nModuli); j++ {
			ctx.ecc.EC_Negate(&cPrime[i][j])
			ctx.ecc.EC_Add(cPrime[i][j], Pm[j], &Pm[j])
		}
	}
	ctx.mapToInt(Pm, m)
}
