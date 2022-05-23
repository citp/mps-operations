package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/profile"
	"github.com/spf13/viper"
)

// #############################################################################

func PrintInfo(logger *log.Logger, protoName, dataDir, resDir string, nParties, nHashes0, nHashesI, intCard, nBits int, showP, eProfile bool) {

	color.Set(color.FgBlue, color.Bold)
	defer color.Unset()

	sep := ": "
	logger.Printf("Time%s%s\n", sep, time.Now().String())
	logger.Printf("Protocol%s%s\n", sep, protoName)
	logger.Printf("Parties%s%d\n", sep, nParties)
	logger.Printf("Delegate%sP_0\n", sep)
	logger.Printf("|X_0|%s%d\n", sep, nHashes0)
	logger.Printf("|X_i|%s%d\n", sep, nHashesI)
	logger.Printf("|I|%s%d\n", sep, intCard)
	logger.Printf("|M|%s%d\n", sep, 1<<nBits)
	logger.Printf("Data%s./%s\n", sep, dataDir)
	logger.Printf("Results%s./%s\n", sep, resDir)
	logger.Printf("Bar%s%s\n", sep, strconv.FormatBool(showP))
	logger.Printf("Profile%s%s\n", sep, strconv.FormatBool(eProfile))
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
	pks := make([]DHElement, nParties+1)

	// Initialize
	watch.Reset()
	NewEGContext(&ctx, 2, 33)
	delegate.Init(0, nParties, nBits, fpaths[0], lPath, showP, &ctx)
	pks[0] = delegate.party.Partial_PubKey()
	times = append(times, watch.Elapsed())

	for i := 1; i <= nParties; i++ {
		watch.Reset()
		parties[i-1].Init(i, nParties, nBits, fpaths[i], lPath, showP, &ctx)
		pks[i] = parties[i-1].Partial_PubKey()
		times = append(times, watch.Elapsed())
	}

	delegate.party.Set_AggPubKey(pks)
	for i := 1; i <= nParties; i++ {
		parties[i-1].Set_AggPubKey(pks)
	}

	return delegate, parties, times
}

func RunProtocol(nParties int, delegate Delegate, parties []Party, proto int) (float64, *big.Int, []time.Duration) {
	var watch Stopwatch
	var times []time.Duration
	// Round1
	var M, R HashMapValues
	var final *HashMapFinal
	M = NewHashMap(delegate.party.nBits)
	sum := (proto%2 == 1)

	watch.Reset()
	delegate.DelegateStart(&M, sum) // TODO: change
	times = append(times, watch.Elapsed())
	for i := 0; i < nParties; i++ {
		if proto <= 1 {
			watch.Reset()
			final = parties[i].MPSI(delegate.L, &M, &R, sum) // TODO: Change
			times = append(times, watch.Elapsed())
		} else {
			watch.Reset()
			final = parties[i].MPSIU(delegate.L, &M, &R, sum) // TODO: Change
			times = append(times, watch.Elapsed())
		}
	}

	// Round2
	fmt.Println("")
	watch.Reset()
	partials := make([][]DHElement, nParties+1)
	cardComputed, ctSum := delegate.DelegateFinish(final, sum)
	// TODO: Change
	times = append(times, watch.Elapsed())

	var computedSum big.Int
	if sum {
		// Round 3
		partials[0] = delegate.party.Partial_Decrypt(ctSum)
		for i := 1; i <= nParties; i++ {
			partials[i] = parties[i-1].Partial_Decrypt(ctSum)
		}
		computedSum = delegate.JointDecryption(ctSum, partials)
	}

	delegate.party.log.Printf("Computation: %d EC point mul.\n", delegate.party.TComputation(proto, &R))
	delegate.party.log.Printf("Communication: %f MB\n", float64(delegate.party.TCommunication(&R))/1e6)
	for i := 0; i < nParties; i++ {
		parties[i].log.Printf("Computation: %d EC point mul.\n", parties[i].TComputation(proto, &R))
		parties[i].log.Printf("Communication: %f MB\n", float64(delegate.party.TCommunication(&R))/1e6)
	}

	return float64(cardComputed), &computedSum, times
}

// #############################################################################

func main() {
	color.Set(color.BgBlue, color.Bold, color.Underline)
	color.Red("Multiparty Private Set Operations")
	color.Unset()

	var nParties, nHashes0, nHashesI, intCard, lim, nBits, proto int
	var dataDir, resDir string
	var eProfile, showP bool

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	Panic(viper.ReadInConfig())

	switch viper.GetString("protocol") {
	case "MPSI":
		proto = 0
	case "MPSI-CA":
		proto = 1
	case "MPSIU":
		proto = 2
	case "MPSIU-CA":
		proto = 3
	}

	nParties = viper.GetInt("n")
	nHashes0 = viper.GetInt("x0")
	nHashesI = viper.GetInt("xi")
	intCard = viper.GetInt("i")
	lim = viper.GetInt("l")
	nBits = viper.GetInt("b")

	dataDir = viper.GetString("data_dir")
	resDir = viper.GetString("result_dir")

	eProfile = viper.GetBool("profile")
	showP = viper.GetBool("progress")

	Assert(proto >= 0 || proto <= 3)
	Assert(nParties > 1)
	Assert(nHashesI > nHashes0)
	Assert(nBits > 9)
	Assert(len(dataDir) > 0)
	Assert(len(resDir) > 0)

	if eProfile {
		defer profile.Start(profile.ProfilePath("./" + resDir)).Stop()
	}

	var watch Stopwatch
	var times []time.Duration
	fpaths := make([]string, nParties+1)
	protoName := []string{"MPSI", "MPSI-CA", "MPSIU", "MPSIU-CA"}
	for i := range fpaths {
		fpaths[i] = path.Join(dataDir, fmt.Sprintf("%d.txt", i))
	}

	_ = os.Mkdir(dataDir, os.ModePerm)
	_ = os.Mkdir(resDir, os.ModePerm)

	data := NewSampleData(nParties+1, nHashes0, nHashesI, intCard, lim, dataDir, false, (proto <= 1))
	res := data.ComputeStats((proto <= 1))
	trueCard, trueSum := res[0], res[1]

	times = append(times, watch.Elapsed())

	delegate, parties, _times := RunInit(nParties, nBits, fpaths, resDir+"/log.txt", showP)
	times = append(times, _times...)

	stdout := log.New(os.Stdout, "", 0)
	loggers := []*log.Logger{parties[0].log, stdout}

	for _, v := range loggers {
		v.SetPrefix("{CONFIG}\t")
		PrintInfo(v, protoName[proto], dataDir, resDir, nParties, nHashes0, nHashesI, intCard, nBits, showP, eProfile)
		fmt.Println("")
	}
	parties[0].log.SetPrefix("[Party 1] ")

	cardComputed, sumComputed, _times := RunProtocol(nParties, delegate, parties, proto)
	times = append(times, _times...)

	e1 := (cardComputed - trueCard) * 100 / trueCard
	color.Green(fmt.Sprintf("{RESULT}\tCount: %d (%d, %f%%)", int(cardComputed), int(trueCard), e1))

	if proto%2 == 1 {
		e2 := (float64(sumComputed.Int64()) - trueSum) * 100 / trueSum
		color.Green(fmt.Sprintf("{RESULT}\tSum: %s (%d, %f%%)", sumComputed.Text(10), int(trueSum), e2))
	}

	Save(proto, nParties, nHashes0, nHashesI, nBits, trueCard, cardComputed, times, resDir+"/timing.csv")

	for _, v := range loggers {
		v.SetPrefix("")
		v.Println("-------------------------------------------")
	}
}

// #############################################################################
