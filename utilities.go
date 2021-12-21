package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"math/rand"
	"os"
	"path"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2b"
)

// #############################################################################

func GetIndex(key string, nBits int) uint64 {
	return HashPrefix([]byte(key), nBits)
}

func GetEmptyMap(sz uint64) map[uint64]bool {
	empty := make(map[uint64]bool, sz)
	for i := uint64(0); i < sz; i++ {
		empty[i] = true
	}
	return empty
}

// #############################################################################

func NewHashMap(nBits int) HashMapValues {
	return HashMapValues{make([]HashMapValue, 1<<nBits), nBits}
}

func (m *HashMapValues) Size() uint64 {
	return uint64(1) << m.nBits
}

// #############################################################################

func CryptographicHash(msg []byte) []byte {
	h := blake2b.Sum256(msg)
	return []byte(h[:])
}

func HashPrefix(msg []byte, sz int) uint64 {
	Assert(sz < 64)
	h := CryptographicHash(msg)
	mask := (uint64(1) << uint64(sz)) - uint64(1)
	return binary.BigEndian.Uint64(h) & mask
}

func Blake2b(buf []byte) []byte {
	ret := blake2b.Sum256(buf)
	return ret[:]
}

// #############################################################################

func RandomScalar(mod *big.Int) *big.Int {
	ret, err := crand.Int(crand.Reader, mod)
	Check(err)
	return ret
}

func RandomBytes(n int) []byte {
	ret := make([]byte, n)
	nR, err := io.ReadFull(crand.Reader, ret)
	Assert(nR == n)
	Check(err)
	return ret
}

func RandomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func RandomNStrings(n int, l int) []string {
	seen := make(map[string]bool)
	ret := make([]string, n)
	idx := 0
	for idx < n {
		s := RandomString(l)
		_, ok := seen[s]
		if !ok {
			ret[idx] = s
			idx += 1
		}
	}
	return ret
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

func GenerateData(nParties, N0, Ni, intCard int, dataDir string) (float64, float64) {
	rand.Seed(time.Now().UnixNano())

	strs := make([][]string, nParties)
	intersection := RandomNStrings(intCard, 12)
	offset := (N0 - intCard)
	U := RandomNStrings((Ni-intCard)*(nParties-1)+offset, 12)

	strs[0] = append(U[:offset], intersection...)
	Assert(len(strs[0]) == N0)
	for i := 1; i < nParties; i++ {
		strs[i] = append(U[offset+(i-1)*(Ni-intCard):offset+i*(Ni-intCard)], intersection...)
		Assert(len(strs[i]) == Ni)
	}

	card1 := IntersectionCardinality(strs)
	card2 := IntersectionWithUnionCardinality(strs)
	Assert(card1 == float64(intCard))

	for i := 0; i < nParties; i++ {
		fpath := path.Join(dataDir, strconv.Itoa(i)+".txt")
		WriteFile(fpath, strs[i])
		strs[i] = ReadFile(fpath)
	}

	Assert(IntersectionCardinality(strs) == float64(intCard))
	Assert(IntersectionWithUnionCardinality(strs) == card2)
	return card1, card2
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

func IntersectionCardinality(Xs [][]string) float64 {
	nParties := len(Xs)
	sets := make([]Set, nParties)
	for i := 0; i < nParties; i++ {
		sets[i] = *NewSet(Xs[i])
	}

	var inter *Set
	if nParties <= 2 {
		inter = &sets[0]
	} else {
		inter = sets[0].Intersection(&sets[1])
	}

	for i := 2; i < nParties; i++ {
		inter = inter.Intersection(&sets[i])
	}

	return float64(inter.Size())
}

func IntersectionWithUnionCardinality(Xs [][]string) float64 {
	nParties := len(Xs)
	sets := make([]Set, nParties)
	for i := 0; i < nParties; i++ {
		sets[i] = *NewSet(Xs[i])
	}

	var union *Set
	if nParties <= 2 {
		union = &sets[1]
	} else {
		union = sets[1].Union(&sets[2])
	}

	for i := 3; i < nParties; i++ {
		union = union.Union(&sets[i])
	}

	union = union.Intersection(&sets[0])
	return float64(union.Size())
}
