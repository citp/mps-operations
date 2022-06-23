package main

import (
	"bytes"
	"crypto/elliptic"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"testing"
	"time"
)

var nParties = flag.Int("n", 3, "no. of parties (excluding delegate)")
var x0 = flag.Int("x0", 100000, "|X_0|")
var xi = flag.Int("xi", 1000000, "|X_i|")
var nBits = flag.Int("mbits", 23, "|M|=|R|=|B|=2^bits")
var nModuli = flag.Int("mod", 3, "no. of CRT moduli")
var maxBits = flag.Int("max", 33, "max size of result")
var logFile = flag.String("log", "results/log.txt", "log file path")

// #############################################################################

func EGSingle(b *testing.B) {
	// fmt.Println("Benchmarking ElGamal")
	var ctx EGContext
	var ct EGCiphertext
	var pk DHElement
	var m, mPrime big.Int

	NewEGContext(&ctx, 3, 35)
	sk := ctx.ecc.RandomScalar()
	ctx.EG_PubKey(sk, &pk)

	for i := 0; i < b.N; i++ {
		m = *ctx.ecc.RandomScalar()
		m.Mod(&m, ctx.N)
		ctx.EG_Encrypt(&pk, &m, &ct)
		ctx.EG_Decrypt(sk, &mPrime, &ct)
		Assert(mPrime.Cmp(&m) == 0)
	}
}

func EGMulti(b *testing.B) {
	// fmt.Println("Benchmarking Multiparty ElGamal")
	var ctx EGContext
	var ct EGCiphertext
	var apk DHElement
	var m, mPrime big.Int

	NewEGContext(&ctx, 3, 35)
	nParties := 5

	sk := make([]*big.Int, nParties)
	pk := make([]DHElement, nParties)
	partials := make([][]DHElement, nParties)
	for i := 0; i < nParties; i++ {
		sk[i] = ctx.ecc.RandomScalar()
		ctx.EGMP_PubKey(sk[i], &pk[i])
	}
	ctx.EGMP_AggPubKey(pk, &apk)

	for i := 0; i < b.N; i++ {
		m = *ctx.ecc.RandomScalar()
		m.Mod(&m, ctx.N)
		ctx.EG_Encrypt(&apk, &m, &ct)
		for j := 0; j < nParties; j++ {
			partials[j] = ctx.EGMP_Decrypt(sk[j], &ct)
		}
		ctx.EGMP_AggDecrypt(partials, &mPrime, &ct)
		Assert(mPrime.Cmp(&m) == 0)
	}
}

func EGArithmetic(b *testing.B) {
	var ctx EGContext
	var ct1, ct2, ct_s EGCiphertext
	var pk DHElement
	var m1, m2, s, sPrime big.Int

	NewEGContext(&ctx, 3, 35)
	sk := ctx.ecc.RandomScalar()
	ctx.EG_PubKey(sk, &pk)

	for i := 0; i < b.N; i++ {
		m1 = *ctx.ecc.RandomScalar()
		m2 = *ctx.ecc.RandomScalar()
		s.Add(&m1, &m2)
		m1.Mod(&m1, ctx.N)
		m2.Mod(&m2, ctx.N)
		s.Mod(&s, ctx.N)
		ctx.EG_Encrypt(&pk, &m1, &ct1)
		ctx.EG_Encrypt(&pk, &m2, &ct2)
		ctx.EG_Add(&ct1, &ct2, &ct_s)
		ctx.EG_Decrypt(sk, &sPrime, &ct_s)
		Assert(sPrime.Cmp(&s) == 0)
	}
}

func EGRerandom(b *testing.B) {
	var ctx EGContext
	var ct EGCiphertext
	var pk DHElement
	var m, mPrime big.Int

	NewEGContext(&ctx, 3, 35)
	sk := ctx.ecc.RandomScalar()
	ctx.EG_PubKey(sk, &pk)

	for i := 0; i < b.N; i++ {
		m = *ctx.ecc.RandomScalar()
		m.Mod(&m, ctx.N)
		ctx.EG_Encrypt(&pk, &m, &ct)
		ctx.EG_Rerandomize(&pk, &ct)
		ctx.EG_Decrypt(sk, &mPrime, &ct)
		Assert(mPrime.Cmp(&m) == 0)
	}
}

func ECCSerialization(b *testing.B) {
	var ctx EGContext
	NewEGContext(&ctx, 3, 35)

	var e, ePrime DHElement
	for i := 0; i < b.N; i++ {
		ctx.ecc.RandomElement(&e)
		eBytes := e.Serialize()
		ePrime = DHElementFromBytes(&ctx.ecc, eBytes)
		Assert(e.x.Cmp(ePrime.x) == 0)
		Assert(e.y.Cmp(ePrime.y) == 0)
	}
}

func EGSerialization(b *testing.B) {
	var ctx EGContext
	var ct, ctPrime EGCiphertext
	var pk DHElement
	var m, mPrime big.Int

	NewEGContext(&ctx, 3, 35)
	sk := ctx.ecc.RandomScalar()
	ctx.EG_PubKey(sk, &pk)

	for i := 0; i < b.N; i++ {
		m = *ctx.ecc.RandomScalar()
		m.Mod(&m, ctx.N)
		ctx.EG_Encrypt(&pk, &m, &ct)
		ctBytes := ctx.EG_Serialize(&ct)
		ctPrime = ctx.EG_Deserialize(ctBytes)
		ctx.EG_Decrypt(sk, &mPrime, &ctPrime)
		Assert(mPrime.Cmp(&m) == 0)
	}
}

func BenchmarkElGamal(b *testing.B) {
	b.Run("Single", EGSingle)
	// b.Run("Multiparty", EGMulti)
	b.Run("Arithmetic", EGArithmetic)
	// b.Run("Re-randomization", EGRerandom)
	b.Run("ECC Serialization", ECCSerialization)
	b.Run("ElGamal Serialization", EGSerialization)
}

// #############################################################################

func RandomPlain(n int) [][]byte {
	pt := make([][]byte, n)
	for i := 0; i < n; i++ {
		pt[i] = RandomBytes(200)
	}
	return pt
}

func EncryptArray(pt [][]byte, key []byte) [][]byte {
	ct := make([][]byte, len(pt))
	for i := 0; i < len(pt); i++ {
		ct[i] = encrypt(pt[i], key)
	}
	return ct
}

func AES(b *testing.B) {
	key := RandomBytes(32)

	b.Run("Encryption", func(b *testing.B) {
		pt := RandomPlain(b.N)
		b.ResetTimer()
		EncryptArray(pt, key)
	})

	b.Run("Decryption", func(b *testing.B) {
		ptPrime := make([][]byte, b.N)
		pt := RandomPlain(b.N)
		ct := EncryptArray(pt, key)
		b.ResetTimer()
		var err error
		for i := 0; i < b.N; i++ {
			ptPrime[i], err = decrypt(ct[i], key)
			Panic(err)
		}
		for i := 0; i < b.N; i++ {
			Assert(bytes.Equal(ptPrime[i], pt[i]))
		}
	})
}

func BenchmarkAES(b *testing.B) {
	b.Run("All", AES)
}

// #############################################################################

func benchmarkInit(b *testing.B, intCard int, proto string, showP bool) (Delegate, []Party, []float64) {
	runtime.GOMAXPROCS(128)
	// debug.SetGCPercent(-1)
	fmt.Println("GOMAXPROCS:", runtime.GOMAXPROCS(0))
	// fmt.Println("GCPercent:", debug.SetGCPercent(-1))
	fmt.Println("nModuli:", uint(*nModuli))
	logger := log.New(os.Stdout, "go test: ", log.Flags())
	defer Timer(time.Now(), logger, "benchmarkInit")

	var ctx EGContext
	var delegate Delegate
	pks := make([]DHElement, *nParties+1)
	parties := make([]Party, *nParties)
	fpaths := []string{"data/0.txt", "data/1.txt", "data/2.txt", "data/3.txt"}

	mpsi := (proto == "MPSI")
	data := NewSampleData(*nParties+1, *x0, *xi, intCard, 1000, "data", false, mpsi)
	res := data.ComputeStats(mpsi)

	NewEGContext(&ctx, uint(*nModuli), uint(*maxBits))
	delegate.Init(0, *nParties, *nBits, fpaths[0], *logFile, showP, &ctx)
	pks[0] = delegate.party.Partial_PubKey()
	for i := 1; i <= *nParties; i++ {
		parties[i-1].Init(i, *nParties, *nBits, fpaths[i], *logFile, showP, &ctx)
		pks[i] = parties[i-1].Partial_PubKey()
	}

	delegate.party.Set_AggPubKey(pks)
	for i := 1; i <= *nParties; i++ {
		parties[i-1].Set_AggPubKey(pks)
	}

	fmt.Println("Finished: Init.")
	return delegate, parties, res
}

func benchmarkU(b *testing.B, sum bool) {
	if sum {
		fmt.Println("Running MPSIU-S")
	} else {
		fmt.Println("Running MPSIU")
	}

	// nParties := 3
	// Ni := 1000000
	// N0 := Ni / 10
	intCard := *x0 / 10
	// nBits := 24
	// nModuli := 3
	// maxBits := 33
	// lim := 1000

	delegate, parties, res := benchmarkInit(b, intCard, "MPSIU", false)
	card := res[0]

	b.ResetTimer()

	// Round 1
	var M, R HashMapValues
	var final *HashMapFinal
	delegate.DelegateStart(&M, sum)
	for i := 0; i < *nParties; i++ {
		final = parties[i].MPSIU(delegate.L, &M, &R, sum)
	}
	fmt.Println("Finished: Round 1.")

	// Round 2
	cardComputed, ctSum := delegate.DelegateFinish(final, sum)
	partials := make([][]DHElement, *nParties+1)
	if sum {
		partials[0] = delegate.party.Partial_Decrypt(ctSum)
		for i := 1; i <= *nParties; i++ {
			partials[i] = parties[i-1].Partial_Decrypt(ctSum)
		}
		fmt.Println("Finished: Round 2.")
	}

	fmt.Printf("Cardinality: %f (true) %d (computed) %f (error)\n", card, cardComputed, ((float64(cardComputed) - card) * 100 / card))

	if sum {
		// Round 3
		computedSum := delegate.JointDecryption(ctSum, partials)
		fmt.Println("Finished: JointDecryption")
		fmt.Println("Sum:", computedSum.Text(10))
	}

	delegate.party.log.Println("---------------------------------")
}

func BenchmarkMPSIUS(b *testing.B) {
	benchmarkU(b, true)
}

func BenchmarkMPSIU_(b *testing.B) {
	benchmarkU(b, false)
}

func BenchmarkMPSIS(b *testing.B) {
	benchmarkI(b, true)
}

func BenchmarkMPSI_(b *testing.B) {
	benchmarkI(b, false)
}

func benchmarkI(b *testing.B, sum bool) {
	if sum {
		fmt.Println("Running MPSI-S")
	} else {
		fmt.Println("Running MPSI")
	}

	// nParties := 3
	// Ni := 100000
	// N0 := Ni / 10
	intCard := *x0 / 10
	// nBits := 20
	// nModuli := 3
	// maxBits := 33
	// lim := 1000

	delegate, parties, res := benchmarkInit(b, intCard, "MPSI", false)
	card := res[0]

	b.ResetTimer()

	// Round 1
	var M, R HashMapValues
	var final *HashMapFinal
	delegate.DelegateStart(&M, sum)
	for i := 0; i < *nParties; i++ {
		final = parties[i].MPSI(delegate.L, &M, &R, sum)
	}
	fmt.Println("Finished: Round 1.")

	// Round 2
	cardComputed, ctSum := delegate.DelegateFinish(final, sum)
	partials := make([][]DHElement, *nParties+1)
	if sum {
		partials[0] = delegate.party.Partial_Decrypt(ctSum)
		for i := 1; i <= *nParties; i++ {
			partials[i] = parties[i-1].Partial_Decrypt(ctSum)
		}
		fmt.Println("Finished: Round 2.")
	}

	fmt.Printf("Cardinality: %f (true) %d (computed) %f (error)\n", card, cardComputed, ((float64(cardComputed) - card) * 100 / card))

	if sum {
		// Round 3
		computedSum := delegate.JointDecryption(ctSum, partials)
		fmt.Println("Finished: JointDecryption")
		fmt.Println("Sum:", computedSum.Text(10))
	}

	delegate.party.log.Println("---------------------------------")
}

func HToC_Tester(t *testing.T, suite string, testRes [][]string, curve elliptic.Curve) {
	var P DHElement
	params, err := NewHtoCParams(suite)
	Panic(err)

	fmt.Println("Testing:", suite)
	msgs := []string{"", "abc", "abcdef0123456789", "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	for i, p := range testRes {
		fmt.Println("msg:", msgs[i])
		HashToCurve_13(msgs[i], &P, curve, params)
		Assert(p[0] == P.x.Text(16))
		Assert(p[1] == P.y.Text(16))
	}
}

func TestHashToCurveIETF13(t *testing.T) {

	HToC_Tester(t, "P256_XMD:SHA-256_SSWU_RO_", [][]string{
		{"2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
			"8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"},
		{"bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f", "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"},
		{"65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
			"cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"},
		{"4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d", "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e"},
		{"457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
			"ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc"},
	}, elliptic.P256())

	HToC_Tester(t, "P384_XMD:SHA-384_SSWU_RO_", [][]string{
		{"eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83", "c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a"},
		{"e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1", "1f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6"},
		{"bdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a5d6b78676400926fbceee6fcd1780fe86e62b2aa89", "57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e0f47e46e4e4b85a0595da29c9494c1814acafe183c"},
		{"3c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a3850e0456f5dd7f7633dd31676d990eda32882ab486c0", "cc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5ea662482b8c1f43dc453a93b94a8026db58f3f5d878"},
		{"7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c5604325f1cdea4c15c10a54ef303aabf2ea58bd9947a4", "ea857285a33abb516732915c353c75c576bf82ccc96adb63c094dde580021eddeafd91f8c0bfee6f636528f3d0c47fd2"},
	}, elliptic.P384())

	HToC_Tester(t, "P521_XMD:SHA-512_SSWU_RO_", [][]string{
		{"fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef3556ed9f7f1bc23cecc9c088", "169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c27166dc3fe5eeef782be411d"},
		{"2f89a1677b28054b50d15e1f81ed6669b5a2158211118ebdef8a6efc77f8ccaa528f698214e4340155abc1fa08f8f613ef14a043717503d57e267d57155cf784a4", "10e0be5dc8e753da8ce51091908b72396d3deed14ae166f66d8ebf0a4e7059ead169ea4bead0232e9b700dd380b316e9361cfdba55a08c73545563a80966ecbb86d"},
		{"6e200e276a4a81760099677814d7f8794a4a5f3658442de63c18d2244dcc957c645e94cb0754f95fcf103b2aeaf94411847c24187b89fb7462ad3679066337cbc4", "1dd8dfa9775b60b1614f6f169089d8140d4b3e4012949b52f98db2deff3e1d97bf73a1fa4d437d1dcdf39b6360cc518d8ebcc0f899018206fded7617b654f6b168"},
		{"1b264a630bd6555be537b000b99a06761a9325c53322b65bdc41bf196711f9708d58d34b3b90faf12640c27b91c70a507998e55940648caa8e71098bf2bc8d24664", "1ea9f445bee198b3ee4c812dcf7b0f91e0881f0251aab272a12201fd89b1a95733fd2a699c162b639e9acdcc54fdc2f6536129b6beb0432be01aa8da02df5e59aaa"},
		{"c12bc3e28db07b6b4d2a2b1167ab9e26fc2fa85c7b0498a17b0347edf52392856d7e28b8fa7a2dd004611159505835b687ecf1a764857e27e9745848c436ef3925", "1cd287df9a50c22a9231beb452346720bb163344a41c5f5a24e8335b6ccc595fd436aea89737b1281aecb411eb835f0b939073fdd1dd4d5a2492e91ef4a3c55bcbd"},
	}, elliptic.P521())
}

func BenchmarkHashToCurveIETF13(b *testing.B) {
	var P DHElement
	params, err := NewHtoCParams("P256_XMD:SHA-256_SSWU_RO_")
	Panic(err)

	for i := 0; i < b.N; i++ {
		msg := RandomString(12)
		HashToCurve_13(msg, &P, elliptic.P256(), params)
	}
}
