package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/pkg/pool"
	"go-port-forward/pkg/retry"

	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

// TCPForwarder listens on a local TCP port and forwards connections to a target.
type TCPForwarder struct {
	listener net.Listener
	rule     *models.ForwardRule
	cancel   context.CancelFunc
	conns    map[net.Conn]struct{}
	svc      *forwardServices // 旁路服务（ACL/日志），测试下可为 nil

	wg sync.WaitGroup

	dialTimeout time.Duration
	bufferSize  int

	// stats (atomic)
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	activeConns atomic.Int64
	totalConns  atomic.Int64
	stopOnce    sync.Once

	connMu sync.Mutex
}

func newTCPForwarder(rule *models.ForwardRule, dialTimeoutSec, bufferSize int) *TCPForwarder {
	if dialTimeoutSec <= 0 {
		dialTimeoutSec = 10
	}
	if bufferSize <= 0 {
		bufferSize = pool.DefaultBufferSize
	}
	return &TCPForwarder{
		rule:        rule,
		dialTimeout: time.Duration(dialTimeoutSec) * time.Second,
		bufferSize:  bufferSize,
		conns:       make(map[net.Conn]struct{}),
	}
}

func (f *TCPForwarder) Start() error {
	listenAddr := fmt.Sprintf("%s:%d", f.rule.ListenAddr, f.rule.ListenPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("TCP 监听失败 | TCP listen failed %s: %w", listenAddr, err)
	}
	f.listener = ln

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	f.wg.Add(1)
	go f.acceptLoop(ctx)
	logger.S.Infow("TCP forwarder started", "rule", f.rule.Name, "listen", listenAddr,
		"target", fmt.Sprintf("%s:%d", f.rule.TargetAddr, f.rule.TargetPort),
		"proxy_protocol", f.rule.ProxyProtocol)
	return nil
}

func (f *TCPForwarder) Stop() {
	f.stopOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		if f.listener != nil {
			_ = f.listener.Close()
		}
		f.closeTrackedConns()
	})
	f.wg.Wait()
}

func (f *TCPForwarder) acceptLoop(ctx context.Context) {
	defer f.wg.Done()
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				if ne, ok := errors.AsType[net.Error](err); ok && ne.Temporary() {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				logger.S.Warnw("TCP accept error", "rule", f.rule.Name, "err", err)
				return
			}
		}
		rule := f.rule
		c := conn
		f.wg.Add(1)
		// Use global goroutine pool via pkg/pool
		if err := pool.Submit(func() { f.handleConn(ctx, c, rule) }); err != nil {
			logger.L.Warn("pool submit failed, running in new goroutine", zap.Error(err))
			go f.handleConn(ctx, c, rule)
		}
	}
}

func (f *TCPForwarder) handleConn(ctx context.Context, src net.Conn, rule *models.ForwardRule) {
	defer f.wg.Done()
	defer src.Close()

	// 访问控制：拒绝的连接直接关闭
	remote, remoteOK := src.RemoteAddr().(*net.TCPAddr)
	if remoteOK && !f.svc.allowed(rule.ID, remote.IP) {
		logger.S.Warnw("TCP source denied by ACL", "rule", rule.Name, "src", remote.String())
		if f.svc != nil {
			f.svc.logEvent(models.ConnLogEntry{
				Protocol: models.ProtocolTCP,
				RuleID:   rule.ID,
				RuleName: rule.Name,
				SrcIP:    remote.IP.String(),
				SrcPort:  remote.Port,
				Event:    models.ConnEventDenied,
			})
		}
		return
	}

	// 通用会话登记（活跃会话视图 + join/leave 日志）
	var si *sessionInfo
	now := time.Now()
	if f.svc != nil && f.svc.sessions != nil && remoteOK {
		key := sessionKey(models.ProtocolTCP, rule.ID, remote)
		si = f.svc.sessions.obtain(key, &sessionInfo{
			key:      key,
			Protocol: models.ProtocolTCP,
			RuleID:   rule.ID,
			RuleName: rule.Name,
			SrcIP:    remote.IP.String(),
			SrcPort:  remote.Port,
			Since:    now,
		})
		f.svc.logEvent(models.ConnLogEntry{
			Protocol: models.ProtocolTCP,
			RuleID:   rule.ID,
			RuleName: rule.Name,
			SrcIP:    remote.IP.String(),
			SrcPort:  remote.Port,
			Event:    models.ConnEventJoin,
		})
		defer func() {
			f.svc.sessions.remove(si.key)
			si.finish(models.ConnEventLeave, f.svc.logs)
		}()
	}

	f.trackConn(src)
	defer f.untrackConn(src)
	f.activeConns.Add(1)
	f.totalConns.Add(1)
	defer f.activeConns.Add(-1)

	target := fmt.Sprintf("%s:%d", rule.TargetAddr, rule.TargetPort)

	// Dial with retry (exponential backoff, max 3 retries, capped at 5s)
	var dst net.Conn
	err := retry.DoWithExponentialCapped(ctx, 3, 500*time.Millisecond, 5*time.Second,
		func(retryCtx context.Context) error {
			dialer := &net.Dialer{Timeout: f.dialTimeout}
			if rule.Transparent {
				// 透明模式：以客户端真实 IP 为源拨号（IP_TRANSPARENT）。
				// 目标是访问码的隧道地址（私网），跳过公网目标检查。
				var srcIP net.IP
				if ra, ok := src.RemoteAddr().(*net.TCPAddr); ok {
					srcIP = ra.IP
				}
				dialer = transparentDialer(retryCtx, srcIP, dialer)
			} else {
				// 通用模式域名目标的安全边界执行点：域名指向哪只有解析后才确定，
				// 在「已解析、未连接」的时机拒绝内网/保留地址，向目标零报文。
				// （API 层只拦「填的就是内网 IP」，拦不住 DNS 指向内网，见 F1。）
				dialer.Control = CheckDialControl
			}
			conn, dialErr := dialer.DialContext(retryCtx, "tcp", target)
			if dialErr != nil {
				return retry.RetryableError(dialErr)
			}
			dst = conn
			return nil
		})
	if err != nil {
		logger.L.Warn("TCP dial failed after retries", zap.String("target", target), zap.Error(err))
		return
	}
	defer dst.Close()
	f.trackConn(dst)
	defer f.untrackConn(dst)

	// PROXY Protocol v2：向目标侧注入携带客户端真实地址的头，仅此一次，
	// 之后的数据原样透传（后端解析端按流读取头并还原真实源地址）。
	if rule.ProxyProtocol {
		hdr := proxyproto.HeaderProxyFromAddrs(0, src.RemoteAddr(), dst.RemoteAddr())
		if _, err := hdr.WriteTo(dst); err != nil {
			logger.L.Warn("PROXY v2 header write failed", zap.String("target", target), zap.Error(err))
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// per-connection 会话字节计数（无会话登记时为 nil）
	var inExtra, outExtra *atomic.Int64
	if si != nil {
		inExtra, outExtra = &si.bytesIn, &si.bytesOut
	}

	// client → target: after EOF from client, half-close the target write side
	go func() {
		defer wg.Done()
		f.copyBufCounting(dst, src, &f.bytesIn, inExtra)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	// target → client: after EOF from target, half-close the client write side
	go func() {
		defer wg.Done()
		f.copyBufCounting(src, dst, &f.bytesOut, outExtra)
		if tc, ok := src.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// countingWriter wraps an io.Writer and atomically accumulates bytes written in real time.
type countingWriter struct {
	w        io.Writer
	counter  *atomic.Int64 // 聚合计数（转发器级）| forwarder-wide counter
	extra    *atomic.Int64 // 可选：单连接计数（会话视图）| optional per-connection counter
}

// countingWriterPool 复用 countingWriter，避免每次连接的双向拷贝各分配一个堆对象。
// countingWriterPool reuses countingWriter to avoid heap allocation per bidirectional copy.
var countingWriterPool = sync.Pool{
	New: func() any { return &countingWriter{} },
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.counter.Add(int64(n))
		if cw.extra != nil {
			cw.extra.Add(int64(n))
		}
	}
	return n, err
}

// reset 清除引用，防止池中对象持有已关闭连接的引用 | Clear references to prevent pooled objects from holding closed connections.
func (cw *countingWriter) reset() {
	cw.w = nil
	cw.counter = nil
	cw.extra = nil
}

// copyBufCounting copies from src to dst using a pooled buffer, updating the
// forwarder-wide counter (and optional per-connection counter) on every write.
// countingWriter 从 sync.Pool 获取，拷贝完成后归还，所有计量在归还前已完成。
// countingWriter is obtained from sync.Pool and returned after copy; all counting is done before return.
func (f *TCPForwarder) copyBufCounting(dst io.Writer, src io.Reader, counter *atomic.Int64, extra *atomic.Int64) {
	buf := pool.GetBuffer(f.bufferSize)
	defer pool.PutBuffer(buf)

	cw := countingWriterPool.Get().(*countingWriter)
	cw.w = dst
	cw.counter = counter
	cw.extra = extra

	_, _ = io.CopyBuffer(cw, src, buf)

	// io.CopyBuffer 是同步调用，到达此处时所有 Write（含计量）已完成，可以安全归还。
	// io.CopyBuffer is synchronous; all Writes (including counting) are done here, safe to return.
	cw.reset()
	countingWriterPool.Put(cw)
}

func (f *TCPForwarder) Stats() (bytesIn, bytesOut, active, total int64) {
	return f.bytesIn.Load(), f.bytesOut.Load(), f.activeConns.Load(), f.totalConns.Load()
}

func (f *TCPForwarder) trackConn(conn net.Conn) {
	if conn == nil {
		return
	}
	f.connMu.Lock()
	f.conns[conn] = struct{}{}
	f.connMu.Unlock()
}

func (f *TCPForwarder) untrackConn(conn net.Conn) {
	if conn == nil {
		return
	}
	f.connMu.Lock()
	delete(f.conns, conn)
	f.connMu.Unlock()
}

func (f *TCPForwarder) closeTrackedConns() {
	f.connMu.Lock()
	conns := make([]net.Conn, 0, len(f.conns))
	for conn := range f.conns {
		conns = append(conns, conn)
	}
	f.connMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}
