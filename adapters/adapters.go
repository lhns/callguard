// Package adapters embeds the JS plugins for harnesses that run extensions
// in-process (opencode, pi). They call "callguard hook generic".
package adapters

import _ "embed"

//go:embed opencode/callguard.js
var opencode string

//go:embed pi/callguard.js
var pi string

// OpenCode returns the opencode 2.x plugin source.
func OpenCode() string { return opencode }

// Pi returns the pi extension source.
func Pi() string { return pi }
