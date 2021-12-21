# Multiparty Private Set Cardinality Operations

## PROTOCOLS
1. MPSI-CA (Intersection Cardinality)
2. MPSIU-CA (Intersection-with-Union Cardinality)

## USAGE
P_0 is the delegated party. Build the executable `micfis` and check usage.
```
go build && ./micfis -h

```
Usage of ./micfis:
  -b int
        number of bits (hash map size = 2^b) (default 17)
  -c    enable profiling
  -d string
        directory containing hashes (default "data")
  -g    generate random hashes and quit
  -h0 int
        |x_0| (default 1000)
  -hi int
        |x_i| (default 10000)
  -i int
        |intersection(x_0,...,x_n)| (default 10000)
  -n int
        number of parties (excluding delegate) (default 3)
  -p int
        protocol (1 = MPSI-CA, 2 = MPSIU-CA) (default 1)
  -r string
        results directory (default "results")
```