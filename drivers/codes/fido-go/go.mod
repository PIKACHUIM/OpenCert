module github.com/globaltrusts/fido-go

go 1.22

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/bulwarkid/virtual-fido v0.0.0-20230103163558-3d5b5e5b5b5b
)

require (
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.10.0 // indirect
)

// 使用本地 virtual-fido 源码（已 clone 到 virtual-fido-ref）
replace github.com/bulwarkid/virtual-fido => ../../../../virtual-fido-ref
