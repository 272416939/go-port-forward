module pfapp

go 1.26

require (
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/kr/pretty v0.3.1 // indirect
	golang.org/x/crypto v0.55.0 // indirect
)

require (
	go-port-forward v0.0.0
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace go-port-forward => ../
