//go:build !linux

package tunnelapp

import "errors"

// 隧道服务端仅支持 Linux（Windows 端运行的是 pf-client）。
func configureInterface(ifaceName, cidr string) error {
	return errors.New("tunnelapp: 隧道服务端仅支持 Linux | tunnel server requires Linux")
}

func setupNAT(tunName, tunCIDR string) error {
	return errors.New("tunnelapp: 隧道服务端仅支持 Linux | tunnel server requires Linux")
}
