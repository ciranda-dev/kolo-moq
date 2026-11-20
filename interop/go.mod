module github.com/ciranda-dev/kolo-moq/interop

// The peer implementation requires Go 1.27, so this module does too; the
// parent module needs Go 1.26.
go 1.27

require (
	github.com/ciranda-dev/kolo-id v0.1.0
	github.com/ciranda-dev/kolo-moq v0.0.0-00010101000000-000000000000
	github.com/ciranda-dev/kolo-secure v0.1.0
	github.com/ciranda-dev/kolo-transport v0.1.0
	github.com/floatdrop/moq-go v0.0.0-20261107175010-4547d8c13e74
)

require (
	github.com/ciranda-dev/kolo-codec v0.1.0 // indirect
	github.com/quic-go/quic-go v0.65.0 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)
