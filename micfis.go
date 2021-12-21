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

func PrintInfo(logger *log.Logger, protoName, dataDir, resDir string, nParties, nHashes0, nHashesI, intCard, nBits int, genOnly, eProfile bool) {

	prefix := "[INFO]"
	tabs := "\t"
	logger.Printf("%s Protocol%s%s\n", prefix, tabs, protoName)
	logger.Printf("%s Parties%s%d\n", prefix, tabs, nParties)
	logger.Printf("%s Delegate%sP_0\n", prefix, tabs)
	logger.Printf("%s |X_0|%s%d\n", prefix, tabs, nHashes0)
	logger.Printf("%s |X_i|%s%d\n", prefix, tabs, nHashesI)
	logger.Printf("%s |I|%s%d\n", prefix, tabs, intCard)
	logger.Printf("%s |M|%s%d\n", prefix, tabs, 1<<nBits)
	logger.Printf("%s Data %s./%s\n", prefix, tabs, dataDir)
	logger.Printf("%s Results %s./%s\n", prefix, tabs, resDir)
	logger.Printf("%s GenOnly %s%s\n", prefix, tabs, strconv.FormatBool(genOnly))
	logger.Printf("%s Profile %s%s\n", prefix, tabs, strconv.FormatBool(eProfile))
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

func RunInit(nParties, nBits int, fpaths []string, lPath string) (Delegate, []Party, []time.Duration) {
	parties := make([]Party, nParties)
	var delegate Delegate
	var watch Stopwatch
	var times []time.Duration

	// Initialize
	watch.Reset()
	delegate.Init(0, nParties, nBits, fpaths[0], lPath)
	times = append(times, watch.Elapsed())

	for i := 1; i <= nParties; i++ {
		watch.Reset()
		parties[i-1].Init(i, nParties, nBits, fpaths[i], lPath)
		times = append(times, watch.Elapsed())
	}

	return delegate, parties, times
}

func RunProtocol(nParties int, delegate Delegate, parties []Party, proto int) (float64, []time.Duration) {
	var watch Stopwatch
	var times []time.Duration
	// Round1
	var R HashMapValues
	watch.Reset()
	delegate.Round1()
	times = append(times, watch.Elapsed())
	for i := 0; i < nParties; i++ {
		if proto == 1 {
			watch.Reset()
			parties[i].MPSI_CA(delegate.L, delegate.M, &R)
			times = append(times, watch.Elapsed())
		} else if proto == 2 {
			watch.Reset()
			parties[i].MPSIU_CA(delegate.L, delegate.M, &R)
			times = append(times, watch.Elapsed())
		}
	}

	// Round2
	watch.Reset()
	cardComputed := delegate.Round2(&R)
	times = append(times, watch.Elapsed())

	return cardComputed, times
}

// #############################################################################

func main() {
	var nParties, nHashes0, nHashesI, intCard, nBits, proto int
	var dataDir, resDir string
	var eProfile, genOnly bool

	flag.IntVar(&proto, "p", 1, "protocol (1 = MPSI-CA, 2 = MPSIU-CA)")
	flag.IntVar(&nParties, "n", 3, "number of parties (excluding delegate)")
	flag.IntVar(&nHashes0, "h0", 1000, "|x_0|")
	flag.IntVar(&nHashesI, "hi", 10000, "|x_i|")
	flag.IntVar(&intCard, "i", 10000, "|intersection(x_0,...,x_n)|")
	flag.IntVar(&nBits, "b", 17, "number of bits (hash map size = 2^b)")
	flag.StringVar(&dataDir, "d", "data", "directory containing hashes")
	flag.StringVar(&resDir, "r", "results", "results directory")
	flag.BoolVar(&eProfile, "c", false, "enable profiling")
	flag.BoolVar(&genOnly, "g", false, "generate random hashes and quit")
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

	stdout := log.New(os.Stdout, "", 0)
	PrintInfo(stdout, protoName[proto-1], dataDir, resDir, nParties, nHashes0, nHashesI, intCard, nBits, genOnly, eProfile)

	_ = os.Mkdir(dataDir, os.ModePerm)
	_ = os.Mkdir(resDir, os.ModePerm)

	card1, card2 := GenerateData(nParties+1, nHashes0, nHashesI, intCard, dataDir)
	card = card1
	if proto == 2 {
		card = card2
	}

	times = append(times, watch.Elapsed())

	if genOnly {
		return
	}

	delegate, parties, _times := RunInit(nParties, nBits, fpaths, resDir+"/log.txt")
	times = append(times, _times...)

	parties[0].log.SetPrefix("")
	parties[0].log.Printf("Time: %d", time.Now().UnixNano())
	PrintInfo(parties[0].log, protoName[proto-1], dataDir, resDir, nParties, nHashes0, nHashesI, intCard, nBits, genOnly, eProfile)
	parties[0].log.SetPrefix("[Party 0] ")

	cardComputed, _times = RunProtocol(nParties, delegate, parties, proto)
	times = append(times, _times...)

	parties[0].log.SetPrefix("")
	parties[0].log.Printf("[Result] true=%d / computed=%d / error percentage=%f\n", int(card), int(cardComputed), ((cardComputed - card) * 100 / card))
	stdout.Printf("[Result] true=%d / computed=%d / error percentage=%f\n", int(card), int(cardComputed), ((cardComputed - card) * 100 / card))

	Save(proto, nParties, nHashes0, nHashesI, nBits, card, cardComputed, times, resDir+"/timing.csv")

	parties[0].log.Println("-------------------------------------------")
}

// #############################################################################
