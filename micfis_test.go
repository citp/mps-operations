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

// func AnalyticResults(nParties, Ni, N0, nBits, intCard int) {
// 	fmt.Printf("E[filled slots]=%f\n", E_FullSlots(1 << nBits, N0))
// }
