package main

import "io"

// STUB: worker C replaces this file with hook.go and plugin.go.

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int { return 2 }
func cmdPlugin(args []string, stdout, stderr io.Writer) int                { return 3 }
