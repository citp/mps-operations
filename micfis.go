package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/profile"
)

// #############################################################################

func PrintInfo(logger *log.Logger, protoName, dataDir, resDir string, nParties, nHashes0, nHashesI, intCard, nBits int, showP, eProfile bool) {
	tabs := "\t"
	logger.Printf("Time%s%s\n", tabs, time.Now().String())
	logger.Printf("Protocol%s%s\n", tabs, protoName)
	logger.Printf("Parties%s%d\n", tabs, nParties)
	logger.Printf("Delegate%sP_0\n", tabs)
	logger.Printf("|X_0|%s%d\n", tabs, nHashes0)
	logger.Printf("|X_i|%s%d\n", tabs, nHashesI)
	logger.Printf("|I|%s%d\n", tabs, intCard)
	logger.Printf("|M|%s%d\n", tabs, 1<<nBits)
	logger.Printf("Data %s./%s\n", tabs, dataDir)
	logger.Printf("Results %s./%s\n", tabs, resDir)
	logger.Printf("Bar %s%s\n", tabs, strconv.FormatBool(showP))
	logger.Printf("Profile %s%s\n", tabs, strconv.FormatBool(eProfile))
}

func Save(proto, nParties, nHashes0, nHashesI, nBits int, card, cardComputed float64, times []time.Duration, fname string) {
	strs := []string{strconv.Itoa(proto), strconv.Itoa(nParties), strconv.Itoa(nHashes0), strconv.Itoa(nHashesI), strconv.Itoa(nBits), fmt.Sprintf("%f", card), fmt.Sprintf("%f", cardComputed)}
	for i := 0; i < len(times); i++ {
		strs = append(strs, times[i].String())
	}
	fline := strings.Join(strs, ",")
	fmt.Println(fline)
	AppendFile(fname, []string{fline})
}

// #############################################################################

func RunInit(nParties, nBits int, fpaths []string, lPath string, showP bool) (Delegate, []Party, []time.Duration) {
	parties := make([]Party, nParties)
	var delegate Delegate
	var watch Stopwatch
	var times []time.Duration
	var ctx EGContext

	// Initialize
	watch.Reset()
	NewEGContext(&ctx, 3, 33)
	delegate.Init(0, nParties, nBits, fpaths[0], lPath, showP, &ctx)
	times = append(times, watch.Elapsed())

	for i := 1; i <= nParties; i++ {
		watch.Reset()
		parties[i-1].Init(i, nParties, nBits, fpaths[i], lPath, showP, &ctx)
		times = append(times, watch.Elapsed())
	}

	return delegate, parties, times
}

func RunProtocol(nParties int, delegate Delegate, parties []Party, proto int) (float64, []time.Duration) {
	var watch Stopwatch
	var times []time.Duration
	// Round1
	var M, R HashMapValues
	var final *HashMapFinal
	M = NewHashMap(delegate.party.nBits)

	watch.Reset()
	delegate.DelegateStart(&M)
	times = append(times, watch.Elapsed())
	for i := 0; i < nParties; i++ {
		if proto == 1 {
			watch.Reset()
			final = parties[i].MPSI_S(delegate.L, &M, &R)
			times = append(times, watch.Elapsed())
		} else if proto == 2 {
			watch.Reset()
			final = parties[i].MPSIU_CA(delegate.L, &M, &R)
			times = append(times, watch.Elapsed())
		}
	}

	// Round2
	watch.Reset()
	cardComputed, _ := delegate.DelegateFinish(final)
	times = append(times, watch.Elapsed())

	delegate.party.log.Printf("Computation: %d EC point mul.\n", delegate.party.TComputation(proto, &R))
	delegate.party.log.Printf("Communication: %f MB\n", float64(delegate.party.TCommunication(&R))/1e6)
	for i := 0; i < nParties; i++ {
		parties[i].log.Printf("Computation: %d EC point mul.\n", parties[i].TComputation(proto, &R))
		parties[i].log.Printf("Communication: %f MB\n", float64(delegate.party.TCommunication(&R))/1e6)
	}

	return float64(cardComputed), times
}

// #############################################################################

func main() {
	// Experiment()
	mainProtocol()
}

func mainProtocol() {
	var nParties, nHashes0, nHashesI, intCard, lim, nBits, proto int
	var dataDir, resDir string
	var eProfile, showP bool

	flag.IntVar(&proto, "p", 1, "protocol (1 = MPSI-CA, 2 = MPSIU-CA)")
	flag.IntVar(&nParties, "n", 3, "number of parties (excluding delegate)")
	flag.IntVar(&nHashes0, "h0", 1000, "|x_0|")
	flag.IntVar(&nHashesI, "hi", 10000, "|x_i|")
	flag.IntVar(&intCard, "i", 1000, "|intersection(x_0,...,x_n)|")
	flag.IntVar(&lim, "l", 1000, "upper bound on associated integers")
	flag.IntVar(&nBits, "b", 17, "number of bits (hash map size = 2^b)")
	flag.StringVar(&dataDir, "d", "data", "directory containing hashes")
	flag.StringVar(&resDir, "r", "results", "results directory")
	flag.BoolVar(&eProfile, "c", false, "enable profiling")
	flag.BoolVar(&showP, "g", false, "show progress")
	flag.Parse()

	Assert(proto == 1 || proto == 2)
	Assert(nParties > 1)
	Assert(nHashesI > nHashes0)
	Assert(nBits > 9)
	Assert(len(dataDir) > 0)
	Assert(len(resDir) > 0)

	if eProfile {
		defer profile.Start(profile.ProfilePath("./" + resDir)).Stop()
	}

	var cardComputed, card float64
	var watch Stopwatch
	var times []time.Duration
	fpaths := make([]string, nParties+1)
	protoName := []string{"MPSI-CA", "MPSIU-CA"}
	for i := range fpaths {
		fpaths[i] = path.Join(dataDir, fmt.Sprintf("%d.txt", i))
	}

	_ = os.Mkdir(dataDir, os.ModePerm)
	_ = os.Mkdir(resDir, os.ModePerm)

	data := NewSampleData(nParties+1, nHashes0, nHashesI, intCard, lim, dataDir, false, (proto == 1))
	res := data.ComputeStats((proto == 1))
	card1, card2 := res[0], res[1]
	card = card1
	if proto == 2 {
		card = card2
	}

	times = append(times, watch.Elapsed())

	delegate, parties, _times := RunInit(nParties, nBits, fpaths, resDir+"/log.txt", showP)
	times = append(times, _times...)

	stdout := log.New(os.Stdout, "", 0)
	loggers := []*log.Logger{parties[0].log, stdout}

	for _, v := range loggers {
		v.SetPrefix("[INFO] ")
		PrintInfo(v, protoName[proto-1], dataDir, resDir, nParties, nHashes0, nHashesI, intCard, nBits, showP, eProfile)
	}
	parties[0].log.SetPrefix("[Party 1] ")

	cardComputed, _times = RunProtocol(nParties, delegate, parties, proto)
	times = append(times, _times...)

	for _, v := range loggers {
		v.SetPrefix("[RSLT] ")
		v.Printf("True\t%d\n", int(card))
		v.Printf("Computed\t%d\n", int(cardComputed))
		v.Printf("Error\t%f\n", ((cardComputed - card) * 100 / card))
	}

	Save(proto, nParties, nHashes0, nHashesI, nBits, card, cardComputed, times, resDir+"/timing.csv")

	for _, v := range loggers {
		v.SetPrefix("")
		v.Println("-------------------------------------------")
	}
}

// #############################################################################
