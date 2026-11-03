//go:build !windows

package main

import "syscall"

func mkfifo(p string) { _ = syscall.Mkfifo(p, 0o644) }
