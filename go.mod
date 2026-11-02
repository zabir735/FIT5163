module succinctgo

go 1.24

require github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1

require (
	github.com/bits-and-blooms/bitset v1.14.2 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.14.0
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace rsc.io/tmplfunc => github.com/rsc/tmplfunc v0.0.3

replace golang.org/x/sys => github.com/golang/sys v0.24.0
