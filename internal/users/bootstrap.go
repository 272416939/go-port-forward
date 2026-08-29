package users

import (
	"fmt"
	"os"
	"path/filepath"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
)

// BootstrapAdminName 是首次启动自动创建的管理员用户名。
const BootstrapAdminName = "admin"

// credentialsFileName 是初始密码的落盘位置（与可执行文件同目录）。
const credentialsFileName = "admin-credentials.txt"

// Bootstrap 在用户表为空时创建初始管理员。
//
// 初始密码同时写日志与一个 0600 文件：日志可能被轮转或采集走，文件可能被
// 运维忽略，两条路都留着才不至于把人锁在门外。返回明文密码供调用方展示。
// MustChangePassword 强制首次登录改密——初始密码在磁盘上留过痕，不能长用。
func (s *Service) Bootstrap() (created bool, username, password string, err error) {
	n, err := s.store.CountUsers()
	if err != nil {
		return false, "", "", err
	}
	if n > 0 {
		return false, "", "", nil
	}

	pw, err := RandomPasswordText()
	if err != nil {
		return false, "", "", err
	}
	u, err := s.Create(&models.CreateUserRequest{
		Username: BootstrapAdminName,
		Password: pw,
		Role:     models.RoleAdmin,
		Comment:  "首次启动自动创建 | created on first run",
	})
	if err != nil {
		return false, "", "", err
	}
	u.MustChangePassword = true
	if err := s.store.SaveUser(u); err != nil {
		return false, "", "", err
	}

	path := credentialsPath()
	body := fmt.Sprintf("go-port-forward 初始管理员账号 | initial administrator\n\n用户名 | username: %s\n密码   | password: %s\n\n首次登录后必须修改密码；改完请删除本文件。\nYou must change this password on first login; delete this file afterwards.\n",
		u.Username, pw)
	if werr := os.WriteFile(path, []byte(body), 0o600); werr != nil {
		logger.S.Warnw("初始密码文件写入失败 | failed to write initial credentials file", "path", path, "err", werr)
	}
	logger.S.Warnw("已创建初始管理员，请立即登录并修改密码 | initial administrator created, log in and change the password now",
		"username", u.Username, "password", pw, "file", path)
	return true, u.Username, pw, nil
}

// RandomPasswordText 生成 16 位随机初始密码。
func RandomPasswordText() (string, error) {
	return auth.RandomPassword(16)
}

func credentialsPath() string {
	exe, err := os.Executable()
	if err != nil {
		return credentialsFileName
	}
	return filepath.Join(filepath.Dir(exe), credentialsFileName)
}
