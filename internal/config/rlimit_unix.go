//go:build unix

package config

import "syscall"

// nofileRlimit returns the process's soft RLIMIT_NOFILE (open-file limit).
// Returns unlimited=true when the limit is effectively unbounded.
func nofileRlimit() (soft int, unlimited bool, err error) {
	var rlim syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return
	}
	soft, unlimited = rlimitCurToSoft(rlim.Cur)
	return soft, unlimited, nil
}

func rlimitCurToSoft(cur uint64) (soft int, unlimited bool) {
	if cur == syscall.RLIM_INFINITY {
		return 0, true
	}

	// Clamp large but finite values so conversion to int is always safe.
	maxInt := int(^uint(0) >> 1)
	if cur > uint64(maxInt) {
		return maxInt, false
	}

	return int(cur), false
}
