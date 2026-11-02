package main

import "io"

// STUB: worker A replaces this file with decide.go and policycmd.go.

func cmdDecide(args []string, stdin io.Reader, stdout, stderr io.Writer) int { return 3 }
func cmdPolicy(args []string, stdout, stderr io.Writer) int                  { return 3 }
