package main

import "testing"

func TestSystemdServiceContentUsesHeadlessTarget(t *testing.T) {
	content := systemdServiceContent("/lpot/reboot.sh")

	for _, want := range []string{
		"Description=LPOT PCIe reboot stability test",
		"ExecStart=/lpot/reboot.sh",
		"After=local-fs.target",
		"WantedBy=multi-user.target",
	} {
		if !contains(content, want) {
			t.Fatalf("service content does not contain %q:\n%s", want, content)
		}
	}
}

func TestShellQuotePreservesArguments(t *testing.T) {
	got := shellQuote("-s 600; reboot")
	want := "'-s 600; reboot'"
	if got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

func contains(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		if value[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
