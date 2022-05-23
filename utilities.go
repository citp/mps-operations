package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/RoaringBitmap/roaring/roaring64"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"lukechampine.com/frand"
)

// #############################################################################

func GetIndex(key string, nBits int) uint64 {
	return HashPrefix([]byte(key), nBits)
}

func GetBitMap(sz uint64) *roaring64.Bitmap {
	m := roaring64.New()
	m.AddRange(0, sz)
	return m
}

// #############################################################################

func NewHashMap(nBits int) HashMapValues {
	m := 1 << nBits
	return HashMapValues{make([]Ciphertext, m), make([]HashMapValue, m), nBits}
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

func AES_KDF(msg []byte) []byte {
	h := blake2b.Sum256(msg)
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
	return frand.Bytes(n)
}

func RandomPrime(n int) *big.Int {
	p, err := crand.Prime(crand.Reader, n)
	Panic(err)
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

func ReadFile(fpath string) map[string]int {
	ret := make(map[string]int)
	file, err := os.Open(fpath)
	Panic(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		arr := strings.Split(scanner.Text(), "\t")
		w := arr[0]
		v, err := strconv.Atoi(arr[1])
		Panic(err)
		ret[w] = v
	}
	Panic(scanner.Err())
	return ret
}

func WriteFile(fpath string, strs map[string]int) {
	os.Remove(fpath)
	file, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY, 0644)
	Panic(err)
	WriteMap(file, strs)
}

func WriteMap(file *os.File, strs map[string]int) {
	datawriter := bufio.NewWriter(file)
	for k, v := range strs {
		_, _ = datawriter.WriteString(k + "\t" + strconv.Itoa(v) + "\n")
	}
	datawriter.Flush()
	file.Close()
}

func WriteArray(file *os.File, strs []string) {
	datawriter := bufio.NewWriter(file)
	for _, data := range strs {
		_, _ = datawriter.WriteString(data + "\n")
	}
	datawriter.Flush()
	file.Close()
}

func AppendFile(fpath string, strs []string) {
	file, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	Panic(err)
	WriteArray(file, strs)
}

// #############################################################################

type SampleData struct {
	X_ADs   []map[string]int
	dataDir string
}

func NewSampleData(nParties, N0, Ni, intCard, lim int, dataDir string, read, mpsi bool) *SampleData {
	var data SampleData
	data.X_ADs = make([]map[string]int, nParties)
	data.dataDir = dataDir

	if read {
		data.Read()
		return &data
	}

	rand.Seed(time.Now().Unix())

	if mpsi {
		data.GenerateI(N0, Ni, intCard, lim)
	} else {
		data.GenerateIU(N0, Ni, intCard, lim)
	}

	data.Write()
	data.Read()

	return &data
}

func (d *SampleData) GenerateI(N0, Ni, intCard, lim int) {
	nParties := len(d.X_ADs)
	sets := make([]Set, nParties)
	var I, U Set
	I.SetRandomN(intCard, 12, lim)
	U.SetRandomN(Ni*nParties*2, 12, lim)
	intersection := I.Serialize()
	for i := 0; i < nParties; i++ {
		sets[i] = *NewSet(intersection)
	}
	Ucount := U.Clone()
	for w := range Ucount.data {
		Ucount.data[w] = 0
	}

	for i := 0; i < nParties; i++ {
		rem := N0
		if i > 0 {
			rem = Ni
		}
		for sets[i].Size() < rem {
			w := Ucount.GetRandom()
			v := Ucount.data[w]
			if v < nParties-1 && !sets[i].Contains(w) {
				sets[i].Add(w, U.data[w])
				Ucount.data[w] = v + 1
			}
		}
		d.X_ADs[i] = sets[i].Serialize()
		Assert(len(d.X_ADs[i]) == rem)
	}

	// fmt.Println(len(sets))
	inter := &sets[0]
	for i := 1; i < nParties; i++ {
		inter = inter.Intersection(&sets[i])
	}

	Assert(inter.Size() == intCard)
}

func (d *SampleData) GenerateIU(N0, Ni, intCard, lim int) {
	nParties := len(d.X_ADs)
	sets := make([]Set, nParties)

	var I, U1, U2 Set
	I.SetRandomN(intCard, 12, lim)
	U1.SetRandomN(N0-intCard, 12, lim)
	U2.SetRandomN(Ni*nParties*2, 12, lim)

	intersection := I.Serialize()
	sets[0] = *NewSet(intersection)
	sets[0] = *sets[0].Union(&U1)
	d.X_ADs[0] = sets[0].Serialize()
	Assert(len(d.X_ADs[0]) == N0)

	for i := 1; i < nParties; i++ {
		sets[i] = *NewSet(map[string]int{})
	}

	for w, v := range intersection {
		num := rand.Intn(nParties-1) + 1
		j := 0
		for j < num {
			idx := rand.Intn(nParties-1) + 1
			if !sets[idx].Contains(w) {
				sets[idx].Add(w, v)
				j++
			}
		}
	}

	Uarr := U2.Clone()
	for i := 1; i < nParties; i++ {
		for sets[i].Size() < Ni {
			w := Uarr.GetRandom()
			if !sets[i].Contains(w) {
				sets[i].Add(w, Uarr.data[w])
			}
		}
		d.X_ADs[i] = sets[i].Serialize()
		Assert(len(d.X_ADs[i]) == Ni)
	}

	union := &sets[1]
	for i := 2; i < nParties; i++ {
		union = union.Union(&sets[i])
	}

	Assert(union.Intersection(&sets[0]).Size() == intCard)
}

func (d *SampleData) Write() {
	for i := 0; i < len(d.X_ADs); i++ {
		fpath := path.Join(d.dataDir, fmt.Sprintf("%d.txt", i))
		WriteFile(fpath, d.X_ADs[i])
	}
}

func (d *SampleData) Read() {
	for i := 0; i < len(d.X_ADs); i++ {
		d.X_ADs[i] = ReadFile(path.Join(d.dataDir, fmt.Sprintf("%d.txt", i)))
	}
}

func (d *SampleData) ComputeStats(mpsi bool) []float64 {
	ret := Cardinality(d.X_ADs, mpsi)
	retFl := make([]float64, len(ret))
	for i, v := range ret {
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

func Panic(err error) {
	if err != nil {
		panic(err)
	}
}

// #############################################################################

func Timer(start time.Time, log *log.Logger, text string) {
	elapsed := time.Since(start)
	log.Printf("%s: %s", text, elapsed)
}

func (w *Stopwatch) Reset() {
	w.start = time.Now()
}
func (w *Stopwatch) Elapsed() time.Duration {
	return time.Since(w.start)
}

// #############################################################################

func NewSet(strs map[string]int) *Set {
	var set Set
	set.data = make(map[string]int)
	for w, v := range strs {
		set.data[w] = v
	}
	return &set
}

func (s *Set) Clone() *Set {
	return NewSet(s.data)
}

func (s *Set) Size() int {
	return len(s.data)
}

func (s *Set) Add(w string, v int) {
	s.data[w] = v
}

func (s *Set) Remove(w string) {
	delete(s.data, w)
}

func (s *Set) Contains(w string) bool {
	_, ok := s.data[w]
	return ok
}

func (s *Set) Intersection(r *Set) *Set {
	i := make(map[string]int)
	for w, v := range r.data {
		vPrime, ok := s.data[w]
		if ok {
			Assert(v == vPrime)
			i[w] = v
		}
	}
	return &Set{i}
}

func (s *Set) Union(r *Set) *Set {
	u := make(map[string]int)
	for w, v := range s.data {
		u[w] = v
	}
	for w, v := range r.data {
		u[w] = v
	}
	return &Set{u}
}

func (s *Set) Difference(r *Set) *Set {
	u := make(map[string]int)
	for w, v := range s.data {
		u[w] = v
	}
	for w := range r.data {
		delete(u, w)
	}
	return &Set{u}
}

func (s *Set) SetRandomN(n int, strl, lim int) {
	s.data = make(map[string]int)
	for len(s.data) < n {
		t := RandomString(strl)
		_, ok := s.data[t]
		if !ok {
			s.data[t] = rand.Int() % lim
		}
	}
}

func (s *Set) GetRandom() string {
	for w := range s.data {
		return w
	}
	return ""
}

func (s *Set) Serialize() map[string]int {
	ret := make(map[string]int)
	for w, v := range s.data {
		ret[w] = v
	}
	return ret
}

func (s *Set) ADSum() int {
	sum := 0
	for _, v := range s.data {
		// fmt.Println(w, "=>", v)
		sum += v
	}
	return sum
}

// #############################################################################

func Cardinality(X_ADs []map[string]int, mpsi bool) []int {
	nParties := len(X_ADs)
	sets := make([]Set, nParties)
	for i := 0; i < nParties; i++ {
		sets[i] = *NewSet(X_ADs[i])
	}

	if mpsi {
		inter := &sets[0]
		for i := 1; i < nParties; i++ {
			inter = inter.Intersection(&sets[i])
		}
		for w := range inter.data {
			Assert(sets[0].Contains(w))
		}
		return []int{inter.Size(), inter.ADSum()}
	} else {
		union := &sets[1]
		for i := 2; i < nParties; i++ {
			union = union.Union(&sets[i])
		}
		union = sets[0].Intersection(union)
		return []int{union.Size(), union.ADSum()}
	}
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
		// fmt.Println(xi)
	}
	fnRate += (1 - E_FullSlots(m, xi)/float64(xi))
	return float64(i) * (1 - fnRate)
}
