package main

import (
	"regexp"
	"strings"
)

// bdfRegex matches a canonical PCI BDF, optionally with a 4-digit domain:
//
//	[domain:]bus:device.function
//	       ^^^ 4 hex   ^^ 2 hex  ^^ 2 hex  ^ 1 hex (0-7)
//
// The sysfs layout under /sys/bus/pci/devices/ always uses this form.
var bdfRegex = regexp.MustCompile(`^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)

// shortBDFRegex matches the domain-less short form "bus:device.function" that
// lspci -s emits in its text output. parseDeviceFile() reads device files in
// this form, so map keys and ignore-list entries must agree to avoid silent
// lookup misses.
var shortBDFRegex = regexp.MustCompile(`^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)

// normalizeBDF returns the short form ("bus:device.function") of a BDF when
// the long form has domain 0000, and the input unchanged otherwise. This
// unifies map keys across the sysfs world (always long) and the lspci-text
// world (always short) on single-domain systems while preserving correctness
// on the very rare multi-domain host.
func normalizeBDF(bdf string) string {
	bdf = strings.TrimSpace(bdf)
	if bdfRegex.MatchString(bdf) && strings.HasPrefix(bdf, "0000:") {
		return bdf[5:]
	}
	return bdf
}
