package main

import (
	"fmt"
	"os"
	"strings"
)

// splitCustomCommandArgs removes -c and treats every following token as the
// custom command argv. LPOT flags must therefore appear before -c.
func splitCustomCommandArgs(args []string) ([]string, []string, error) {
	for i, arg := range args[1:] {
		if arg != "-c" && !strings.HasPrefix(arg, "-c=") {
			continue
		}

		index := i + 1
		var custom []string
		if strings.HasPrefix(arg, "-c=") {
			if value := strings.TrimPrefix(arg, "-c="); value != "" {
				custom = append(custom, value)
			}
			custom = append(custom, args[index+1:]...)
		} else {
			custom = append(custom, args[index+1:]...)
		}
		if len(custom) == 0 || custom[0] == "" {
			return nil, nil, fmt.Errorf("-c requires a command and optional arguments")
		}
		return append([]string{args[0]}, args[1:index]...), custom, nil
	}
	return args, nil, nil
}

func flagWasProvided(name string) bool {
	prefix := "-" + name
	for _, arg := range os.Args[1:] {
		if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
			return true
		}
	}
	return false
}

var customCommandArgs []string

func applyDefaultDurationForBareT() {
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] != "-t" {
			continue
		}
		if i+1 == len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
			os.Args[i] = "-t=12"
		}
	}
}

// Show help
func showHelp(programName string) {
	fmt.Printf("Usage: %s [OPTIONS]\n", programName)
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Author: Nephom,Chiang (Integrated by AI)\n")
	fmt.Printf("Running without -t only shows this help menu.\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -t <hours>   Setup runtime, default is 12 hours.\n")
	fmt.Printf("  -tm <count>  Reboot exactly this many times (test mode).\n")
	fmt.Printf("  -d <secs>    Setup delay time for driver ready, default is 300 seconds.\n")
	fmt.Printf("  -s <secs>    Setup delay time for reboot, default is 300 seconds.\n")
	fmt.Printf("  -p           Stop and disable future reboots on topology, raw config, or lspci differences.\n")
	fmt.Printf("  -c <command> Run the command and all following arguments in the background on every boot; output goes to %s. LPOT options must come before -c.\n", COMMAND_USER_LOG)
	fmt.Printf("  -r           Reset /lpot directory and clean all files.\n")
	fmt.Printf("  -scan        Scan USB/bridge/volatile devices and write /lpot/ignore_list.txt, then exit.\n")
	fmt.Printf("  -classify    Print and save the PCI link-capability report, then exit.\n")
	fmt.Printf("  -ui          Open the local read-only result dashboard.\n")
	fmt.Printf("  -h, --help   Show Help menu\n")
	fmt.Printf("\nNote: Every -t run automatically checks PCIe link status and scans for unstable bytes \u2014 you do not need to run these separately.\n")
	fmt.Printf("\nExample:\n")
	fmt.Printf("  %s -t 24 -s 600    Run reboot during 24 hours and each reboot wait for 600 seconds\n", programName)
	fmt.Printf("  %s -r              Reset /lpot directory to clean state\n", programName)
	fmt.Printf("  %s -scan           Only scan PCI devices and generate ignore bits file\n", programName)
	fmt.Printf("  %s -classify       Print and save link-capability keep/skip decisions\n", programName)
	fmt.Printf("  %s -t              Run the default 12-hour reboot test\n", programName)
	fmt.Printf("  %s -tm 2           Reboot exactly two times\n", programName)
	fmt.Printf("  %s -t 24 -c /usr/bin/ping -t 192.168.1.1    Run ping in the background on every boot\n", programName)
}
