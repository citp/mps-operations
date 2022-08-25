## Multiparty Private Set Operations

A Go implementation of the protocols for {MPSI, MPSIU, MPSI-Sum, MPSIU-Sum} described in _Estimating Incidental Collection in Foreign Intelligence Surveillance: Large-Scale Multiparty Private Set Intersection with Union and Sum_. All references are to sections and figures in the paper.

### Files

| File                      | Description                                                                               |
| :-----------------------: | :---------------------------------------------------------------------------------------- |
| `aes.go`                  | Authenticated Encryption with Associated Data (AEAD) primitives (Section 4.1)             |
| `config.yml`              | Configuration                                                                             |
| `delegate.go`             | `Delegate-Start` (Figure 9), `Delegate-Finish` (Figure 11), `Joint-Decryption` (Figure 7) |
| `dh.go`                   | `DH.Reduce` (Section 4.1)                                                                 |
| `elgamal.go`              | Partial Homomorphic Encryption (PHE) primitives (Section 4.1)                             |
| `hash_to_curve.go`        | Implements https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13         |
| `mps_operations_test.go`  | Unit tests                                                                                |
| `mps_operations.go`       | Contains `main()`                                                                         |
| `party.go`                | `BlindEncrypt` (Figure 10), `MPSI` (Figure 12), `MPSIU-Sum` (Figure 13)                   |
| `pool.go`                 | Thread pool primitives                                                                    |
| `types.go`                | Defines all used types                                                                    |
| `utilities.go`            | Utility functions for generating data, benchmarking etc.                                  |
| `workers.go`              | Functions for thread pool workers                                                         |

### Requirements

Either `Go` (1.18) or `Docker` (20.10.12).

### Usage

Update `config.yml` as desired

```
# Required
protocol: "MPSI-Sum"        # Protocol to run: MPSI / MPSI-Sum / MPSIU / MPSIU-Sum
n: 3                        # Number of participants (excluding delegate)
x0: 32768                   # Size of delegate's input set
xi: 32768                   # Size of non-delegates' input sets
i: 1024                     # Size of the intersection / intersection-with-union
b: 17                       # log_2(Size of hash map)
data_dir: "./data"          # Location of generated identifiers
result_dir: "./results"     # Location of results
l: 1024                     # Upper bound on generated associated integers (for MPSI-Sum / MPSIU-Sum)

# Optional
profile: false              # Disable profiling
```

#### Native

```
go build -o mps_operations
./mps_operations
```

#### Docker

```
docker build -t mps_operations .
docker run -it --rm --name mps_operations mps_operations
```

### Notes

* The program generates 12-character random strings as identifiers (and associated integer values in case of MPSI-Sum / MPSIU-Sum) for each party. See `RandomString` in `utilities.go` for more information. The input set for party $i$ is written to `data_dir/i.txt`.

Sample output:
```
&6ucfjGTd(7X	538
0kFoHEbAlh!L	20
@ATFtoOeydoN	386
%gS0YCy2Fo0z	429
SCl@LiQsfvLi	17
```

* Results are written to `stdout` and appended to `results_dir/bench.csv`.

Sample output:
```
protocol,n,x0,xi,b,i,i_computed,init_*,DelegateStart,protocol_*,DelegateFinish
MPSI-Sum,3,32768,32768,17,1024.000000,677.000000,15.099722ms,18.330426ms,15.737076ms,7.892617ms,4.672172268s,2.805618562s,3.077387929s,9.027740391s,1.931292339s
MPSI-Sum,3,32768,32768,17,1024.000000,672.000000,20.467008ms,30.362544ms,26.849409ms,31.211263ms,3.971302925s,2.196969842s,2.274308749s,5.310224164s,1.007233662s
MPSI-Sum,3,32768,32768,17,1024.000000,658.000000,13.88427ms,12.477244ms,13.983926ms,10.315089ms,3.930134756s,2.182335303s,2.319216396s,5.398680827s,1.003784134s
```

* The program uses goroutines for parallelization. The number of goroutines is equal to the number of logical cores available.

### Cite This Work

```
@software{mps_operations,
    author = {Kulshrestha, Anunay and Mayer, Jonathan},
    month = {6},
    title = {{Multiparty Private Set Operations}},
    url = {https://github.com/citp/mps-operations},
    year = {2022}
}
```
