package main

import (
	"strings"
	"testing"
)

func TestSystemdServiceContentKeepsTargetOrderingAcyclic(t *testing.T) {
	content := systemdServiceContent("/lpot/reboot.sh", "multi-user.target")
	if strings.Contains(content, "After=multi-user.target") {
		t.Fatalf("service must not order itself after its WantedBy target:\n%s", content)
	}
	if !strings.Contains(content, "After=local-fs.target\n") {
		t.Fatalf("expected local filesystem ordering:\n%s", content)
	}
	if !strings.Contains(content, "WantedBy=multi-user.target\n") {
		t.Fatalf("expected requested install target:\n%s", content)
	}
}

func TestSystemdServiceContentSupportsGraphicalTarget(t *testing.T) {
	content := systemdServiceContent("/lpot/reboot.sh", "graphical.target")
	if !strings.Contains(content, "WantedBy=graphical.target\n") {
		t.Fatalf("expected graphical install target:\n%s", content)
	}
	if strings.Contains(content, "After=graphical.target") {
		t.Fatalf("service must not order itself after its WantedBy target:\n%s", content)
	}
}
