package models

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	_ "time/tzdata" // 嵌入标准 IANA 时区数据，确保全平台（包括精简环境）免依赖宿主机 /usr/share/zoneinfo
)

// DefaultTimezone 是系统全局默认时区（中国标准时间 UTC+8）。
const DefaultTimezone = "Asia/Shanghai"

var systemLocation atomic.Pointer[time.Location]

func init() {
	loc, err := time.LoadLocation(DefaultTimezone)
	if err != nil {
		loc = time.FixedZone("CST", 8*3600)
	}
	systemLocation.Store(loc)
	time.Local = loc
}

// SystemLocation 获取当前系统配置的全局时区（并发安全，原子无锁读取）。
func SystemLocation() *time.Location {
	loc := systemLocation.Load()
	if loc == nil {
		return time.Local
	}
	return loc
}

// SystemTimezoneName 返回当前系统时区名称。
func SystemTimezoneName() string {
	loc := SystemLocation()
	if loc == nil {
		return DefaultTimezone
	}
	return loc.String()
}

// ApplyTimezone 校验并原子切换系统配置时区。
//
// 进程内所有后续的 models.Now()、日志与日期格式化将即时采用新时区，
// 无需重启服务，且不产生任何并发数据竞争。
func ApplyTimezone(tz string) error {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		tz = DefaultTimezone
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return fmt.Errorf("无效的时区标识 %q | invalid timezone %q: %w", tz, tz, err)
	}
	systemLocation.Store(loc)
	return nil
}

// Now 返回系统配置时区下的当前时间。
//
// 后端生成业务时间戳（如创建时间、更新时间、诊断时间）的统一入口。
func Now() time.Time {
	return time.Now().In(SystemLocation())
}

// InSystemTimezone 将任意时间转换到系统配置时区。若 t 为零值则直接返回。
func InSystemTimezone(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.In(SystemLocation())
}

// FormatDate 按系统配置时区将时间格式化为 YYYY-MM-DD。
func FormatDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return InSystemTimezone(t).Format("2006-01-02")
}

// FormatDateTime 按系统配置时区将时间格式化为 YYYY-MM-DD 15:04:05。
func FormatDateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return InSystemTimezone(t).Format("2006-01-02 15:04:05")
}

// CalendarDaysDiff 计算在系统配置时区下 target 相对于 base 的自然日历天数差。
//
// 先将两时间分别转换为系统时区对应自然日中午 12 点（UTC 锚定计算），
// 严格对齐自然日且规避可能存在的夏令时 23/25 小时跳变：
// (targetDate - baseDate) / (24h)
func CalendarDaysDiff(target, base time.Time) int {
	if target.IsZero() || base.IsZero() {
		return 0
	}
	loc := SystemLocation()
	tIn := target.In(loc)
	bIn := base.In(loc)
	tDate := time.Date(tIn.Year(), tIn.Month(), tIn.Day(), 12, 0, 0, 0, time.UTC)
	bDate := time.Date(bIn.Year(), bIn.Month(), bIn.Day(), 12, 0, 0, 0, time.UTC)
	return int(tDate.Sub(bDate) / (24 * time.Hour))
}
