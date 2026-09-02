//go:build !linux

package tunnelapp

import "errors"

// 隧道服务端仅支持 Linux（Windows 端运行的是 pf-client）。
func configureInterface(ifaceName, cidr string) error {
	return errors.New("tunnelapp: 隧道服务端仅支持 Linux | tunnel server requires Linux")
}

func setupReturnPath(tunName string) error {
	return errors.New("tunnelapp: 隧道服务端仅支持 Linux | tunnel server requires Linux")
}

func teardownReturnPath(tunName string) {}

// verifyReturnPath 仅在 Linux 上有意义（非 Linux 的隧道服务端在 Start 就会
// 失败，守护协程没有启动的机会）；留桩只为编译。
func verifyReturnPath(tunName string) (bool, error) {
	return false, errors.New("tunnelapp: 隧道服务端仅支持 Linux | tunnel server requires Linux")
}
