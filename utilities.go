package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"path"
	"sort"
	"time"

	"github.com/RoaringBitmap/roaring/roaring64"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// #############################################################################
var _p *big.Int

func GetIndex(key string, nBits int) uint64 {
	// var err error
	// if _p.Cmp(big.NewInt(0)) == 0 {
	// 	_p, err = crand.Prime(crand.Reader, nBits)
	// 	Check(err)
	// }
	// h := big.NewInt(int64(HashPrefix([]byte(key), nBits+1)))
	// h = h.Mod(h, _p)
	// return h.Uint64()
	return HashPrefix([]byte(key), nBits)
}

// func GetEmptyMap(sz uint64) map[uint64]bool {
// 	empty := make(map[uint64]bool, sz)
// 	for i := uint64(0); i < sz; i++ {
// 		empty[i] = true
// 	}
// 	return empty
// }

func GetBitMap(sz uint64) *roaring64.Bitmap {
	m := roaring64.New()
	m.AddRange(0, sz)
	return m
}

// #############################################################################

func NewHashMap(nBits int) HashMapValues {
	return HashMapValues{make([]HashMapValue, 1<<nBits), nBits}
}

func (m *HashMapValues) Size() uint64 {
	return uint64(1) << m.nBits
}

// #############################################################################

func BLAKE2S(msg []byte, domainSep string) []byte {
	h := blake2s.Sum256(append([]byte(domainSep), msg...))
	return []byte(h[:])
}

func BLAKE2B(msg []byte, domainSep string) []byte {
	h := blake2b.Sum256(append([]byte(domainSep), msg...))
	return []byte(h[:])
}

func HashPrefix(msg []byte, sz int) uint64 {
	Assert(sz < 64)
	h := BLAKE2S(msg, "HashPrefix")
	mask := (uint64(1) << uint64(sz)) - uint64(1)
	return binary.BigEndian.Uint64(h) & mask
}

// #############################################################################

func RandomBytes(n int) []byte {
	ret := make([]byte, n)
	nR, err := io.ReadFull(crand.Reader, ret)
	Assert(nR == n)
	Check(err)
	return ret
}

func RandomPrime(n int) *big.Int {
	p, err := crand.Prime(crand.Reader, n)
	Check(err)
	return p
}

func RandomString(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// #############################################################################

func ReadFile(fpath string) []string {
	var ret []string
	file, err := os.Open(fpath)
	Check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ret = append(ret, scanner.Text())
	}
	Check(scanner.Err())

	sort.Slice(ret, func(i, j int) bool {
		return ret[i] < ret[j]
	})
	return ret
}

func WriteFile(fpath string, strs []string) {
	os.Remove(fpath)
	file, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY, 0644)
	Check(err)
	Write(file, strs)
}

func Write(file *os.File, strs []string) {
	datawriter := bufio.NewWriter(file)
	for _, data := range strs {
		_, _ = datawriter.WriteString(data + "\n")
	}
	datawriter.Flush()
	file.Close()
}

func AppendFile(fpath string, strs []string) {
	file, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	Check(err)
	Write(file, strs)
}

// #############################################################################

type SampleData struct {
	Xs      [][]string
	dataDir string
}

func NewSampleData(nParties, N0, Ni, intCard int, dataDir string, read, mpsi bool) *SampleData {
	var data SampleData
	data.Xs = make([][]string, nParties)
	data.dataDir = dataDir

	if read {
		data.Read()
		return &data
	}

	if mpsi {
		data.GenerateI(N0, Ni, intCard)
	} else {
		data.GenerateIU(N0, Ni, intCard)
	}
	data.Write()
	data.Read()

	return &data
}

func (d *SampleData) GenerateI(N0, Ni, intCard int) {
	nParties := len(d.Xs)
	rand.Seed(42)
	sets := make([]Set, nParties)
	var I, U Set
	I.RandomN(intCard, 12)
	U.RandomN(Ni*nParties*2, 12)
	intersection := I.Serialize()
	for i := 0; i < nParties; i++ {
		sets[i] = *NewSet(intersection)
	}
	Ucount := make(map[string]int)
	Uarr := U.Serialize()
	for i := 0; i < U.Size(); i++ {
		Ucount[Uarr[i]] = 0
	}

	for i := 0; i < nParties; i++ {
		rem := N0
		if i > 0 {
			rem = Ni
		}
		for sets[i].Size() < rem {
			k := Uarr[rand.Intn(len(Uarr))]
			v := Ucount[k]
			if v < nParties-1 && !sets[i].Contains(k) {
				sets[i].Add(k)
				Ucount[k] = v + 1
			}
		}
		d.Xs[i] = sets[i].Serialize()
		Assert(len(d.Xs[i]) == rem)
	}

	for k := 0; k < nParties; k++ {
		sort.Slice(d.Xs[k], func(i, j int) bool {
			return d.Xs[k][i] < d.Xs[k][j]
		})
	}
}

func (d *SampleData) GenerateIU(N0, Ni, intCard int) {
	rand.Seed(42)
	nParties := len(d.Xs)
	sets := make([]Set, nParties)

	var I, U1, U2 Set
	I.RandomN(intCard, 12)
	U1.RandomN(N0-intCard, 12)
	U2.RandomN(Ni*nParties*2, 12)

	intersection := I.Serialize()
	sets[0] = *NewSet(intersection)
	sets[0] = *sets[0].Union(&U1)
	d.Xs[0] = sets[0].Serialize()
	Assert(len(d.Xs[0]) == N0)

	for i := 1; i < nParties; i++ {
		sets[i] = *NewSet([]string{})
	}

	for i := 0; i < len(intersection); i++ {
		num := rand.Intn(nParties-1) + 1
		for j := 0; j < num; j++ {
			idx := rand.Intn(nParties-1) + 1
			// fmt.Println(idx)
			sets[idx].Add(intersection[i])
		}
	}

	Uarr := U2.Serialize()
	for i := 1; i < nParties; i++ {
		for sets[i].Size() < Ni {
			k := Uarr[rand.Intn(len(Uarr))]
			if !sets[i].Contains(k) {
				sets[i].Add(k)
			}
		}
		d.Xs[i] = sets[i].Serialize()
		Assert(len(d.Xs[i]) == Ni)
	}

	union := &sets[1]
	for i := 2; i < nParties; i++ {
		union = union.Union(&sets[i])
	}

	for k := 0; k < nParties; k++ {
		sort.Slice(d.Xs[k], func(i, j int) bool {
			return d.Xs[k][i] < d.Xs[k][j]
		})
	}
}

func (d *SampleData) Write() {
	for i := 0; i < len(d.Xs); i++ {
		fpath := path.Join(d.dataDir, fmt.Sprintf("%d.txt", i))
		WriteFile(fpath, d.Xs[i])
	}
}

func (d *SampleData) Read() {
	for i := 0; i < len(d.Xs); i++ {
		d.Xs[i] = ReadFile(path.Join(d.dataDir, fmt.Sprintf("%d.txt", i)))
	}
}

func (d *SampleData) ComputeStats() []float64 {
	ret := Cardinality(d.Xs)

	retFl := make([]float64, len(ret))
	for i, v := range ret {
		// fmt.Printf("%d, %d\n", i, v)
		retFl[i] = float64(v)
	}

	return retFl
}

// #############################################################################

func Assert(v bool) {
	if !v {
		panic("Assertion failed")
	}
}

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

// #############################################################################

func Timer(start time.Time, log *log.Logger) {
	elapsed := time.Since(start)
	log.Printf("%s", elapsed)
}

func (w *Stopwatch) Reset() {
	w.start = time.Now()
}
func (w *Stopwatch) Elapsed() time.Duration {
	return time.Since(w.start)
}

// #############################################################################

func NewSet(strs []string) *Set {
	var set Set
	set.data = make(map[string]bool)
	for _, s := range strs {
		set.data[s] = true
	}
	return &set
}

func (s *Set) Size() int {
	return len(s.data)
}

func (s *Set) Add(t string) {
	s.data[t] = true
}

func (s *Set) Remove(t string) {
	delete(s.data, t)
}

func (s *Set) Contains(t string) bool {
	_, ok := s.data[t]
	return ok
}

func (s *Set) Intersection(r *Set) *Set {
	i := make(map[string]bool)
	for k := range r.data {
		if s.data[k] {
			i[k] = true
		}
	}
	return &Set{i}
}

func (s *Set) Union(r *Set) *Set {
	u := make(map[string]bool)
	for k := range s.data {
		u[k] = true
	}
	for k := range r.data {
		u[k] = true
	}
	return &Set{u}
}

func (s *Set) Difference(r *Set) *Set {
	u := make(map[string]bool)
	for k := range s.data {
		u[k] = true
	}
	for k := range r.data {
		delete(u, k)
	}
	return &Set{u}
}

func (s *Set) RandomN(n int, l int) {
	s.data = make(map[string]bool)
	for len(s.data) < n {
		t := RandomString(l)
		_, ok := s.data[t]
		if !ok {
			s.data[t] = true
		}
	}
}

func (s *Set) Serialize() []string {
	ret := make([]string, s.Size())
	idx := 0
	for k := range s.data {
		ret[idx] = k
		idx += 1
	}
	return ret
}

// #############################################################################

func Cardinality(Xs [][]string) []int {
	nParties := len(Xs)
	sets := make([]Set, nParties)
	for i := 0; i < nParties; i++ {
		sets[i] = *NewSet(Xs[i])
	}

	var ret []int
	inter := &sets[0]
	// fmt.Println("inter.size", inter.Size())
	for i := 1; i < nParties; i++ {
		inter = inter.Intersection(&sets[i])
		// fmt.Println("inter.size", inter.Size())
		ret = append(ret, inter.Size())
	}

	for i := 1; i < nParties; i++ {
		ret = append(ret, sets[0].Intersection(&sets[i]).Size())
	}

	union := &sets[1]
	for i := 2; i < nParties; i++ {
		union = union.Union(&sets[i])
	}
	ret = append(ret, sets[0].Intersection(union).Size())
	return ret
}

// func IntersectionWithUnionCardinality(Xs [][]string) float64 {
// 	nParties := len(Xs)
// 	sets := make([]Set, nParties)
// 	for i := 0; i < nParties; i++ {
// 		sets[i] = *NewSet(Xs[i])
// 	}

// 	var union *Set
// 	if nParties <= 2 {
// 		union = &sets[1]
// 	} else {
// 		union = sets[1].Union(&sets[2])
// 	}

// 	for i := 3; i < nParties; i++ {
// 		union = union.Union(&sets[i])
// 	}

// 	union = union.Intersection(&sets[0])
// 	return float64(union.Size())
// }

// #############################################################################

func NewProgressBar(sz int, color, name string) *progressbar.ProgressBar {
	return progressbar.NewOptions(sz,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetWidth(20),
		progressbar.OptionSetDescription(fmt.Sprintf("[%s]%s...[reset]", color, name)),
		progressbar.OptionShowIts(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))
}

// #############################################################################

func E_FullSlots(n, N0 float64) float64 {
	return float64(n) * (1.0 - math.Pow((float64(n)-1.0)/float64(n), float64(N0)))
}

func E_SlotCollision(m, s, xi float64) float64 {
	return s * (1.0 - math.Pow(((m-s)/m), xi))
}

func E_Collisions(m, x float64) float64 {
	return x - m + (m * math.Pow((1.0-(1.0/m)), x))
}

func E_Intersection(m, x0, xi, i0, i float64, nParties int, mpsi bool) float64 {
	return E_FN(m, x0, xi, i, nParties, mpsi) + E_FP(m, x0, xi, i0, i, nParties, mpsi)
}

// nParties does not include delegate
func E_FP(m, x0, xi, i0, i float64, nParties int, mpsi bool) float64 {
	if mpsi {
		return E_FullSlots(m, i0-i) * math.Pow((E_FullSlots(m, xi-i)/m), float64(nParties-1))
	}
	return 0
}

// nParties does not include delegate
func E_FN(m, x0, xi, i float64, nParties int, mpsi bool) float64 {
	fnRate := (1 - E_FullSlots(m, x0)/float64(x0))

	// fmt.Println(m, x0, xi, i, nParties, mpsi)
	if !mpsi {
		xi *= float64(nParties)
		xi -= i
		fmt.Println(xi)
	}
	fnRate += (1 - E_FullSlots(m, xi)/float64(xi))
	return float64(i) * (1 - fnRate)
}
