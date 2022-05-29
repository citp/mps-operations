# Multiparty Private Set Operations

## Requirements
 * `go` $>= 1.18$ or `docker`

## Protocols
1. MPSI (`MPSI`)
2. MPSI-Sum (`MPSI-Sum`)
3. MPSIU (`MPSIU`)
4. MPSIU-Sum (`MPSIU-Sum`)

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
