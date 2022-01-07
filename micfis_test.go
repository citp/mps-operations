package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// #############################################################################

func BenchmarkMPSIU_CA(b *testing.B) {
	nParties := 3
	Ni := 10000
	N0 := Ni / 10
	nBits := 20
	data := NewSampleData(nParties+1, N0, Ni, N0/10, "data", false, false)
	res := data.ComputeStats()
	card := res[1]

	// _, card := GenerateData(nParties+1, N0, Ni, N0/10, "data")

	parties := make([]Party, nParties)
	var delegate Delegate

	fpaths := []string{"data/0.txt", "data/1.txt", "data/2.txt", "data/3.txt"}

	// Initialize
	delegate.Init(0, nParties, nBits, fpaths[0], "results/log.txt", false)
	for i := 1; i <= nParties; i++ {
		parties[i-1].Init(i, nParties, nBits, fpaths[i], "results/log.txt", false)
	}

	fmt.Println("Finished: Init.")

	// Round1
	var M, R HashMapValues
	delegate.Round1(&M)
	for i := 0; i < nParties; i++ {
		parties[i].MPSIU_CA(delegate.L, &M, &R)
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
	data := NewSampleData(nParties+1, N0, Ni, N0/10, "data", false, true)
	res := data.ComputeStats()
	card := res[0]

	parties := make([]Party, nParties)
	var delegate Delegate

	fpaths := []string{"data/0.txt", "data/1.txt", "data/2.txt", "data/3.txt"}

	// Initialize
	delegate.Init(0, nParties, nBits, fpaths[0], "results/log.txt", false)
	for i := 1; i <= nParties; i++ {
		parties[i-1].Init(i, nParties, nBits, fpaths[i], "results/log.txt", false)
	}

	fmt.Println("Finished: Init.")

	// Round1
	var M, R HashMapValues
	delegate.Round1(&M)
	for i := 0; i < nParties; i++ {
		parties[i].MPSI_CA(delegate.L, &M, &R)
	}

	fmt.Println("Finished: Round 1.")
	cardComputed := delegate.Round2(&R)
	fmt.Println("Finished: Round 2.")

	fmt.Printf("Cardinality: %f (true) %f (computed) %f (error)\n", card, cardComputed, ((cardComputed - card) * 100 / card))
}

func TestHashToCurveIETF13(t *testing.T) {
	// P256_XMD:SHA-256_SSWU_RO_
	var ctx DHContext
	var P DHElement
	NewDHContext(&ctx)

	testVec := map[string][]string{
		"": {"2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
			"8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"},
		"abc": {"bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f", "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"},
		"abcdef0123456789": {"65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
			"cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"},
		"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq": {"4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d", "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e"},
		"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
			"457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
			"ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc"},
	}

	for v := range testVec {
		p := testVec[v]
		fmt.Println("Testing:", v)
		ctx.HashToCurve_13(v, &P)
		assert.EqualValues(t, p[0], P.x.Text(16))
		assert.EqualValues(t, p[1], P.y.Text(16))
	}
}

func BenchmarkHashToCurveIETF13(b *testing.B) {
	var ctx DHContext
	var P DHElement
	NewDHContext(&ctx)

	for i := 0; i < b.N; i++ {
		msg := RandomString(12)
		ctx.HashToCurve_13(msg, &P)
	}
}

func BenchmarkHashToCurveBruteForce(b *testing.B) {
	var ctx DHContext
	var P DHElement
	NewDHContext(&ctx)

	for i := 0; i < b.N; i++ {
		msg := RandomString(12)
		ctx.HashToCurve(msg, &P)
	}
}
