package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
)

func certOwnerScope(r *http.Request) (string, bool) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		return "", false
	}
	if !me.IsAdmin() {
		return me.ID, true
	}
	return r.URL.Query().Get("user_id"), true
}

func (h *handler) ownedCert(w http.ResponseWriter, r *http.Request) (*models.Certificate, bool) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return nil, false
	}
	id := r.PathValue("id")
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "证书管理服务未就绪 | certificate service unavailable")
		return nil, false
	}
	cert, err := h.certs.Get(id)
	if err != nil {
		fail(w, http.StatusNotFound, "证书不存在 | certificate not found")
		return nil, false
	}
	if !me.IsAdmin() && cert.UserID != "" && cert.UserID != me.ID {
		fail(w, http.StatusNotFound, "证书不存在 | certificate not found")
		return nil, false
	}
	return cert, true
}

func (h *handler) listCertificates(w http.ResponseWriter, r *http.Request) {
	scope, authed := certOwnerScope(r)
	if !authed {
		unauthorized(w)
		return
	}
	if h.certs == nil {
		ok(w, []*models.Certificate{})
		return
	}
	certs, err := h.certs.List(scope)
	if err != nil {
		internalError(w, err)
		return
	}
	userMap := make(map[string]string)
	for _, c := range certs {
		if c.UserID != "" {
			if name, ok := userMap[c.UserID]; ok {
				c.UserName = name
			} else if u, uerr := h.users.Get(c.UserID); uerr == nil {
				userMap[c.UserID] = u.Username
				c.UserName = u.Username
			}
		}
		if h.mgr != nil {
			c.UsedCount = h.mgr.CountRulesByCert(c.ID)
		}
	}
	if certs == nil {
		certs = []*models.Certificate{}
	}
	ok(w, certs)
}

func (h *handler) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "证书管理服务未就绪 | certificate service unavailable")
		return
	}
	var req models.UploadCertificateRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := me
	if me.IsAdmin() && req.UserID != "" && req.UserID != me.ID {
		got, gerr := h.users.Get(req.UserID)
		if gerr != nil {
			writeUserError(w, gerr)
			return
		}
		owner = got
	}
	cert, err := h.certs.Upload(owner, &req)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	createdWithMessage(w, cert, "证书已上传并保存 | certificate uploaded")
}

func (h *handler) applyACMECertificate(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "证书管理服务未就绪 | certificate service unavailable")
		return
	}
	var req models.ApplyACMERequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := me
	if me.IsAdmin() && req.UserID != "" && req.UserID != me.ID {
		got, gerr := h.users.Get(req.UserID)
		if gerr != nil {
			writeUserError(w, gerr)
			return
		}
		owner = got
	}
	cert, err := h.certs.ApplyACME(r.Context(), owner, &req)
	if err != nil {
		fail(w, http.StatusBadRequest, fmt.Sprintf("ACME 证书申请失败: %v | ACME issue failed: %v", err, err))
		return
	}
	createdWithMessage(w, cert, "证书申请成功并已保存 | certificate issued successfully")
}

// prepareManualDNSCertificate 执行手动 DNS 解析第一步：返回待添加的 TXT 记录。
func (h *handler) prepareManualDNSCertificate(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "证书管理服务未就绪 | certificate service unavailable")
		return
	}
	var req models.ApplyACMERequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := me
	if me.IsAdmin() && req.UserID != "" && req.UserID != me.ID {
		got, gerr := h.users.Get(req.UserID)
		if gerr != nil {
			writeUserError(w, gerr)
			return
		}
		owner = got
	}
	res, err := h.certs.PrepareManualDNS(r.Context(), owner, &req)
	if err != nil {
		fail(w, http.StatusBadRequest, fmt.Sprintf("获取 DNS 记录失败: %v | failed to prepare DNS challenge: %v", err, err))
		return
	}
	ok(w, res)
}

// verifyManualDNSCertificate 执行第二步：用户已添加 TXT 记录，提交验证并签发。
func (h *handler) verifyManualDNSCertificate(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "证书管理服务未就绪 | certificate service unavailable")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, err := h.certs.CompleteManualDNS(r.Context(), req.Token)
	if err != nil {
		fail(w, http.StatusBadRequest, fmt.Sprintf("证书签发失败: %v | issuance failed: %v", err, err))
		return
	}
	_ = me
	createdWithMessage(w, cert, "证书签发成功并已保存 | certificate issued and saved")
}

func (h *handler) getCertificate(w http.ResponseWriter, r *http.Request) {
	cert, allowed := h.ownedCert(w, r)
	if !allowed {
		return
	}
	if h.mgr != nil {
		cert.UsedCount = h.mgr.CountRulesByCert(cert.ID)
	}
	ok(w, cert)
}

func (h *handler) updateCertificate(w http.ResponseWriter, r *http.Request) {
	cert, allowed := h.ownedCert(w, r)
	if !allowed {
		return
	}
	var req models.UpdateCertificateRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	next, err := h.certs.Update(cert.ID, &req)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	okWithMessage(w, next, "证书已更新 | certificate updated")
}

func (h *handler) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	cert, allowed := h.ownedCert(w, r)
	if !allowed {
		return
	}
	if h.mgr != nil {
		if n := h.mgr.CountRulesByCert(cert.ID); n > 0 {
			ruleNames := h.mgr.RuleNamesByCert(cert.ID)
			fail(w, http.StatusConflict, fmt.Sprintf("该证书还被 %d 条转发规则使用（%s），请先修改或删除那些规则 | certificate still in use by: %s",
				n, strings.Join(ruleNames, ", "), strings.Join(ruleNames, ", ")))
			return
		}
	}
	if err := h.certs.Delete(cert.ID); err != nil {
		if err == storage.ErrCertNotFound {
			fail(w, http.StatusNotFound, "证书不存在 | certificate not found")
			return
		}
		internalError(w, err)
		return
	}
	okWithMessage(w, nil, "证书已删除 | certificate deleted")
}

func (h *handler) renewCertificate(w http.ResponseWriter, r *http.Request) {
	cert, allowed := h.ownedCert(w, r)
	if !allowed {
		return
	}
	next, err := h.certs.Renew(r.Context(), cert.ID)
	if err != nil {
		fail(w, http.StatusBadRequest, fmt.Sprintf("证书续签失败: %v | renewal failed: %v", err, err))
		return
	}
	okWithMessage(w, next, "证书续签成功 | certificate renewed successfully")
}

// getACMEConfig handles GET /api/acme-config (仅管理员)
func (h *handler) getACMEConfig(w http.ResponseWriter, r *http.Request) {
	if h.certs == nil {
		ok(w, (*models.GlobalACMEConfig)(nil).View())
		return
	}
	v, err := h.certs.GlobalACMEConfig()
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, v)
}

// updateACMEConfig handles PUT /api/acme-config (仅管理员)
func (h *handler) updateACMEConfig(w http.ResponseWriter, r *http.Request) {
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "证书管理服务未就绪 | certificate service unavailable")
		return
	}
	var req models.UpdateGlobalACMEConfigRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := h.certs.UpdateGlobalACMEConfig(&req)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	okWithMessage(w, v, "全局 ACME 配置已更新 | global ACME configuration updated")
}

// getPublicACMEStatus handles GET /api/certificates/acme/status (全部已登录用户)
func (h *handler) getPublicACMEStatus(w http.ResponseWriter, r *http.Request) {
	if h.certs == nil {
		ok(w, models.PublicACMEStatus{})
		return
	}
	st, err := h.certs.PublicACMEStatus()
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, st)
}
// --- DNS 提供商凭据管理 ---

func (h *handler) ownedDNSCredential(w http.ResponseWriter, r *http.Request) (*models.DNSCredential, bool) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		fail(w, http.StatusUnauthorized, "未登录 | unauthorized")
		return nil, false
	}
	id := r.PathValue("id")
	if id == "" {
		fail(w, http.StatusBadRequest, "缺少凭据 ID | credential id required")
		return nil, false
	}
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "服务未就绪 | service unavailable")
		return nil, false
	}
	cred, err := h.certs.GetDNSCredential(id)
	if err != nil {
		if errors.Is(err, storage.ErrDNSCredentialNotFound) {
			fail(w, http.StatusNotFound, "DNS 凭据不存在 | DNS credential not found")
			return nil, false
		}
		internalError(w, err)
		return nil, false
	}
	if !me.IsAdmin() && cred.UserID != "" && cred.UserID != me.ID {
		fail(w, http.StatusNotFound, "DNS 凭据不存在 | DNS credential not found")
		return nil, false
	}
	return cred, true
}

func (h *handler) listDNSCredentials(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		fail(w, http.StatusUnauthorized, "未登录 | unauthorized")
		return
	}
	if h.certs == nil {
		ok(w, []models.DNSCredentialView{})
		return
	}
	list, err := h.certs.ListDNSCredentials(me.ID, me.IsAdmin())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, list)
}

func (h *handler) createDNSCredential(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		fail(w, http.StatusUnauthorized, "未登录 | unauthorized")
		return
	}
	if h.certs == nil {
		fail(w, http.StatusServiceUnavailable, "服务未就绪 | service unavailable")
		return
	}
	var req models.SaveDNSCredentialRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := me
	if me.IsAdmin() && req.UserID != "" {
		if got, err := h.users.Get(req.UserID); err == nil && got != nil {
			owner = got
		}
	}
	view, err := h.certs.CreateDNSCredential(owner, &req)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	okWithMessage(w, view, "DNS 凭据已保存 | DNS credential saved")
}

func (h *handler) getDNSCredential(w http.ResponseWriter, r *http.Request) {
	cred, allowed := h.ownedDNSCredential(w, r)
	if !allowed {
		return
	}
	ok(w, cred.View())
}

func (h *handler) updateDNSCredential(w http.ResponseWriter, r *http.Request) {
	cred, allowed := h.ownedDNSCredential(w, r)
	if !allowed {
		return
	}
	var req models.SaveDNSCredentialRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	view, err := h.certs.UpdateDNSCredential(cred.ID, &req)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	okWithMessage(w, view, "DNS 凭据已更新 | DNS credential updated")
}

func (h *handler) deleteDNSCredential(w http.ResponseWriter, r *http.Request) {
	cred, allowed := h.ownedDNSCredential(w, r)
	if !allowed {
		return
	}
	if err := h.certs.DeleteDNSCredential(cred.ID); err != nil {
		if errors.Is(err, storage.ErrDNSCredentialNotFound) {
			fail(w, http.StatusNotFound, "DNS 凭据不存在 | DNS credential not found")
			return
		}
		internalError(w, err)
		return
	}
	okWithMessage(w, nil, "DNS 凭据已删除 | DNS credential deleted")
}


