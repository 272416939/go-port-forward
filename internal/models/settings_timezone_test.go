package models

import (
	"sync"
	"testing"
	"time"
)

func TestDefaultTimezoneAndNormalization(t *testing.T) {
	if DefaultTimezone != "Asia/Shanghai" {
		t.Fatalf("DefaultTimezone should be Asia/Shanghai, got %q", DefaultTimezone)
	}

	def := DefaultSettings()
	if def.Timezone != DefaultTimezone {
		t.Fatalf("DefaultSettings().Timezone should be %q, got %q", DefaultTimezone, def.Timezone)
	}

	raw := Settings{}
	norm := NormalizeSettings(raw)
	if norm.Timezone != DefaultTimezone {
		t.Fatalf("NormalizeSettings should fill default timezone, got %q", norm.Timezone)
	}
}

func TestValidateSettingsTimezone(t *testing.T) {
	validZones := []string{"Asia/Shanghai", "UTC", "America/New_York", "Asia/Tokyo", "Europe/London", ""}
	for _, tz := range validZones {
		s := DefaultSettings()
		s.Timezone = tz
		if err := ValidateSettings(&s); err != nil {
			t.Fatalf("timezone %q should be valid, got err: %v", tz, err)
		}
	}

	invalidZones := []string{"Invalid/Zone", "Mars/Crater", "FooBar"}
	for _, tz := range invalidZones {
		s := DefaultSettings()
		s.Timezone = tz
		if err := ValidateSettings(&s); err == nil {
			t.Fatalf("timezone %q should be rejected", tz)
		}
	}
}

func TestApplyTimezoneAndConversions(t *testing.T) {
	// 切换到 Asia/Shanghai
	if err := ApplyTimezone("Asia/Shanghai"); err != nil {
		t.Fatalf("ApplyTimezone failed: %v", err)
	}
	if SystemTimezoneName() != "Asia/Shanghai" {
		t.Fatalf("expected Asia/Shanghai, got %q", SystemTimezoneName())
	}

	// UTC 2026-10-12 00:00:00 -> Shanghai 2026-10-12 08:00:00
	utcTime := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	shTime := InSystemTimezone(utcTime)
	if shTime.Hour() != 8 || shTime.Day() != 12 {
		t.Fatalf("expected 08:00 on 12th, got %v", shTime)
	}

	if got := FormatDate(utcTime); got != "2026-10-12" {
		t.Fatalf("expected 2026-10-12, got %q", got)
	}
	if got := FormatDateTime(utcTime); got != "2026-10-12 08:00:00" {
		t.Fatalf("expected 2026-10-12 08:00:00, got %q", got)
	}

	// 日历天数计算验证：
	// Base: 北京时间 2026-10-12 08:00:00 (UTC 00:00:00)
	base := utcTime
	// Target1: UTC 2027-01-09 23:30:00 -> 北京时间 2027-01-10 07:30:00 (同一自然日)
	target1 := time.Date(2027, 1, 9, 23, 30, 0, 0, time.UTC)
	// Target2: UTC 2027-01-10 02:00:00 -> 北京时间 2027-01-10 10:00:00 (同一自然日)
	target2 := time.Date(2027, 1, 10, 2, 0, 0, 0, time.UTC)
	// Target3: UTC 2027-01-09 15:00:00 -> 北京时间 2027-01-09 23:00:00 (前一个自然日)
	target3 := time.Date(2027, 1, 9, 15, 0, 0, 0, time.UTC)

	diff1 := CalendarDaysDiff(target1, base)
	diff2 := CalendarDaysDiff(target2, base)
	diff3 := CalendarDaysDiff(target3, base)

	if diff1 != 90 || diff2 != 90 {
		t.Fatalf("target1 and target2 are both 2027-01-10 in Shanghai, should both be 90 days: got diff1=%d diff2=%d", diff1, diff2)
	}
	if diff3 != 89 {
		t.Fatalf("target3 is 2027-01-09 in Shanghai, should be 89 days: got %d", diff3)
	}

	// 零值时间保护
	if CalendarDaysDiff(time.Time{}, base) != 0 || CalendarDaysDiff(target1, time.Time{}) != 0 {
		t.Fatalf("zero time should yield 0 days diff")
	}
}

func TestCurrentUserIncludesTimezone(t *testing.T) {
	_ = ApplyTimezone("Asia/Shanghai")
	u := &User{
		ID:       "test-id",
		Username: "admin",
		Role:     RoleAdmin,
	}
	view := u.View(Quota{})
	if view.Timezone != "Asia/Shanghai" {
		t.Fatalf("expected view.Timezone=Asia/Shanghai, got %q", view.Timezone)
	}
}

func TestApplyTimezoneConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 并发读取 Now() 和 InSystemTimezone()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = Now()
					_ = InSystemTimezone(time.Now())
					_ = SystemTimezoneName()
				}
			}
		}()
	}

	// 并发切换时区
	zones := []string{"Asia/Shanghai", "UTC", "Asia/Tokyo", "America/New_York"}
	for i := 0; i < 50; i++ {
		_ = ApplyTimezone(zones[i%len(zones)])
		time.Sleep(time.Millisecond)
	}

	close(stop)
	wg.Wait()

	// 恢复默认时区
	_ = ApplyTimezone(DefaultTimezone)
}
