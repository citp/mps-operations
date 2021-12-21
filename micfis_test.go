package main

import (
	"fmt"
	"testing"
)

// #############################################################################

func BenchmarkMPSIU_CA(b *testing.B) {
	nParties := 3
	Ni := 10000
	N0 := Ni / 10
	nBits := 20
	_, card := GenerateData(nParties+1, N0, Ni, N0/10, "data")

	parties := make([]Party, nParties)
	var delegate Delegate

	fpaths := []string{"data/0.txt", "data/1.txt", "data/2.txt", "data/3.txt"}

	// Initialize
	delegate.Init(0, nParties, nBits, fpaths[0], "results/log.txt")
	for i := 1; i <= nParties; i++ {
		parties[i-1].Init(i, nParties, nBits, fpaths[i], "results/log.txt")
	}

	fmt.Println("Finished: Init.")

	// Round1
	var R HashMapValues
	delegate.Round1()
	for i := 0; i < nParties; i++ {
		parties[i].MPSIU_CA(delegate.L, delegate.M, &R)
	}
	fmt.Println("Finished: Round 1.")

	cardComputed := delegate.Round2(&R)
	fmt.Println("Finished: Round 2.")

	fmt.Printf("Cardinality: %f (true) %f (computed) %f (error)\n", card, cardComputed, ((cardComputed - card) * 100 / card))
}

func BenchmarkMPSI_CA(b *testing.B) {
	nParties := 3
	Ni := 10000
	N0 := Ni / 10
	nBits := 20
	card, _ := GenerateData(nParties+1, N0, Ni, N0/10, "data")

	parties := make([]Party, nParties)
	var delegate Delegate

	fpaths := []string{"data/0.txt", "data/1.txt", "data/2.txt", "data/3.txt"}

	// Initialize
	delegate.Init(0, nParties, nBits, fpaths[0], "results/log.txt")
	for i := 1; i <= nParties; i++ {
		parties[i-1].Init(i, nParties, nBits, fpaths[i], "results/log.txt")
	}

	fmt.Println("Finished: Init.")

	// Round1
	delegate.Round1()
	var R HashMapValues
	for i := 0; i < nParties; i++ {
		parties[i].MPSI_CA(delegate.L, delegate.M, &R)
	}

	fmt.Println("Finished: Round 1.")
	cardComputed := delegate.Round2(&R)
	fmt.Println("Finished: Round 2.")

	fmt.Printf("Cardinality: %f (true) %f (computed) %f (error)\n", card, cardComputed, ((cardComputed - card) * 100 / card))
}

// func BenchmarkDH(b *testing.B) {
// 	n := 1000000
// 	var L DHElement

// 	ctx := NewDHContext()
// 	sk := ctx.RandomScalar()
// 	ctx.EC_BaseMultiply(sk, &L)

// 	H := make([]DHElement, n)
// 	P := make([]DHElement, n)
// 	Q := make([]DHElement, n)
// 	S := make([]DHElement, n)

// 	for i := 0; i < n; i++ {
// 		r := ctx.RandomScalar()
// 		ctx.EC_BaseMultiply(r, &H[i])
// 		ctx.EC_Multiply(sk, H[i], &P[i])
// 	}

// 	b.ResetTimer()
// 	b.ReportAllocs()

// for i := 0; i < b.N; i++ {
// 	ctx.DH_Reduce_Parallel(P, L, H, 8, &Q, &S)
// }

// for i := 0; i < n; i++ {
// 	var t DHElement
// 	ctx.EC_Multiply(sk, Q[i], &t)
// 	Assert(t.x.Cmp(S[i].x) == 0 && t.y.Cmp(S[i].y) == 0)
// }
// }

// func TestHashMap(t *testing.T) {
// 	n_bits := 30
// 	fmt.Println("n_bits =", n_bits)
// 	sz := (1 << n_bits)
// 	x := make([][]byte, sz)
// 	m := make([]bool, sz)
// 	// idx := make(*big.Int, sz)
// 	for i := 0; i < sz/8; i++ {
// 		x[i] = RandomBytes(20)
// 		idx := HashPrefix(x[i], n_bits)
// 		// fmt.Println(i, idx)
// 		Assert(!m[idx])
// 		// if m[idx] {
// 		// panic()
// 		// }
// 		m[idx] = true
// 	}

// 	// fmt.Println("Hello World")
// 	// fmt.Println(CryptographicHash([]byte("Suar")))
// }
