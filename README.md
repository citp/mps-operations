# Multiparty Private Set Cardinality Operations

## PROTOCOLS
1. MPSI (`MPSI_`)
2. MPSIU-Sum (`MPSIUS`)

## USAGE
```
go test -args -help
```


## TESTING

```
go test -timeout 0 -bench <protocol> -run=TestZ -args -x0 <|X_0|> -xi <|X_i|> -mbits <log_2(map size)> -mod <no. of CRT moduli> -log <path/to/log/file>
```
