# Multiparty Private Set Operations

## Requirements
 * `go` $\geq$ 1.18 or `docker`

## Protocols
1. `MPSI` 
2. `MPSI-Sum` 
3. `MPSIU` 
4. `MPSIU-Sum`

## Usage

Update `config.yml` as desired. 

### Native

```
go build; ./mps_operations
```

### Docker

```
docker build -t mps_operations .
docker run -it --rm --name mps_operations mps_operations
```
