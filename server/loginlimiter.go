package server

import (
	"sync"
	"time"
)

// Login-failure rate limiter: keeps a sliding-window count per IP and per account; once the
// failure count within the window exceeds the threshold, it locks for a cooldown period. State
// lives in process memory (good enough for a single-instance deployment, clearing on restart is
// acceptable) and does not write to the DB, to avoid persisting every failure and amplifying the
// attack surface. Key events such as lock/unlock are written to the audit log by the caller and
// can be viewed on the logs page.
//
// Why two dimensions: locking by account only -> an attacker can spam wrong credentials against an
// account to lock the legitimate user out (DoS); adding an IP lock -> a single source sweeping many
// usernames is also stopped by the IP lock. A hit on either bucket rejects the request.

type loginBucket struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginBucket
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{buckets: map[string]*loginBucket{}}
}

// loginPolicy holds the limiter's tunable parameters, read from settings (safe defaults when unset).
type loginPolicy struct {
	enabled       bool
	userThreshold int
	ipThreshold   int
	window        time.Duration
	cooldown      time.Duration
}

// loginPolicy assembles the current policy: each field can be overridden by settings, invalid values fall back to the default.
func (s *Server) loginPolicy() loginPolicy {
	pol := loginPolicy{
		enabled:       true,
		userThreshold: 10,
		ipThreshold:   30,
		window:        15 * time.Minute,
		cooldown:      15 * time.Minute,
	}
	if s.m == nil || s.m.pg == nil {
		return pol
	}
	pg := s.m.pg
	pol.enabled = pg.GetBool("auth.lockout_enabled", true)
	if v := pg.GetInt("auth.lockout_user_threshold", 0); v > 0 {
		pol.userThreshold = v
	}
	if v := pg.GetInt("auth.lockout_ip_threshold", 0); v > 0 {
		pol.ipThreshold = v
	}
	if v := pg.GetInt("auth.lockout_window_minutes", 0); v > 0 {
		pol.window = time.Duration(v) * time.Minute
	}
	if v := pg.GetInt("auth.lockout_cooldown_minutes", 0); v > 0 {
		pol.cooldown = time.Duration(v) * time.Minute
	}
	return pol
}

func ipKey(ip string) string     { return "ip:" + ip }
func userKey(user string) string { return "u:" + user }

// locked reports whether the IP or account is in a lock cooldown, and returns the remaining cooldown duration (the larger of the two buckets).
func (l *loginLimiter) locked(ip, user string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var remain time.Duration
	for _, k := range []string{ipKey(ip), userKey(user)} {
		if b := l.buckets[k]; b != nil && now.Before(b.lockedUntil) {
			if r := time.Until(b.lockedUntil); r > remain {
				remain = r
			}
		}
	}
	return remain > 0, remain
}

// fail records one failure into the IP bucket and the account bucket. Returns true when this failure
// causes some bucket to [newly enter] the locked state (so the caller can write a lock audit entry).
// When the policy is disabled it records no state and locked is always false.
func (l *loginLimiter) fail(ip, user string, pol loginPolicy) bool {
	if !pol.enabled {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now, pol)
	newlyLocked := false
	if l.recordLocked(ipKey(ip), now, pol.window, pol.cooldown, pol.ipThreshold) {
		newlyLocked = true
	}
	if user != "" && l.recordLocked(userKey(user), now, pol.window, pol.cooldown, pol.userThreshold) {
		newlyLocked = true
	}
	return newlyLocked
}

// recordLocked records one failure on a bucket, slides the window if needed, and sets the cooldown
// expiry once the threshold is reached. Returns true when this call is exactly what triggered the
// lock. The caller holds l.mu.
func (l *loginLimiter) recordLocked(key string, now time.Time, window, cooldown time.Duration, threshold int) bool {
	b := l.buckets[key]
	if b == nil {
		b = &loginBucket{windowStart: now}
		l.buckets[key] = b
	}
	if now.Sub(b.windowStart) > window {
		b.windowStart = now
		b.count = 0
	}
	b.count++
	if b.count >= threshold {
		b.lockedUntil = now.Add(cooldown)
		b.count = 0
		b.windowStart = now
		return true
	}
	return false
}

// reset clears the failure counts for the IP and account (called on a successful login).
func (l *loginLimiter) reset(ip, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, ipKey(ip))
	delete(l.buckets, userKey(user))
}

// sweepLocked, when the bucket count grows large, clears stale buckets that are neither locked nor
// within an active window, to prevent a flood of distinct usernames/sources from bloating the map
// into memory pressure. The caller holds l.mu.
func (l *loginLimiter) sweepLocked(now time.Time, pol loginPolicy) {
	if len(l.buckets) < 4096 {
		return
	}
	for k, b := range l.buckets {
		if now.After(b.lockedUntil) && now.Sub(b.windowStart) > pol.window {
			delete(l.buckets, k)
		}
	}
}
