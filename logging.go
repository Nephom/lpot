package main

import (
	"fmt"
	"os"
)

// logWarn writes a consistently-formatted warning to stderr. All ad hoc
// "Warning: ..." fmt.Fprintf(os.Stderr, ...) call sites should be replaced
// with this so the prefix, capitalization, and trailing newline never drift.
func logWarn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// logWarnFp writes the same warning both to a log file and to stderr, with a
// timestamp prefix on the log-file copy. Use this for warnings that happen
// during a reboot cycle and should be visible in reboot.log as well.
func logWarnFp(logFp *os.File, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
	if logFp != nil {
		fmt.Fprintf(logFp, "%s %sWarning: %s\n", getCurrentTimestamp(), cycleTag(), msg)
	}
}
