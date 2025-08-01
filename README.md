# LPOT

## Overview
The LPOT is a utility designed to automate scan PCIe devices and manage system reboots on specified Linux distributions.

## Requirements
- **Operating Systems:** This tool is supported on or above version:
  - Red Hat Enterprise Linux 9 (RHEL9)
  - SLES 15 SP5
  - Ubuntu 22.04

## Installation
To use LPOT, ensure it has been installed in your system's `/lpot` directory. Follow the installation instructions provided by the software vendor.

## Usage
LPOT operates through two main command sequences:

### Step 1: Initial Setup and Execution
```bash
lpot<version>.run
```
This command initiates the LPOT tool with its base version settings. It prepares the environment for subsequent operations.

### Step 2: Configuration and Run
After executing the initial setup, you can configure and run LPOT using the following command:

To create ignore_bits.txt in /lpot folder
```bash
configscan -scan
```
After you check ignore.txt as you wished(like USB device), then run
```bash
lpot -t <hours> -d <seconds> -s <seconds> -p
```
Where:
- `-t`: Specifies the number of hours after which the system should reboot. (Example: `-t 24`)
- `-d`: Sets the delay in seconds before each scheduled reboot starts. This helps distribute load over time. (Example: `-d 300`)
- `-s`: Sets the waiting time to wait devices ready. (Default: 300 seconds)
- `-p`: If this flag is used, LPOT will monitor the system for any errors during the process and halt further reboots if an error is detected.

## Example
To schedule the system to reboot every 24 hours with a 5-minute delay and wait 60 seconds to reboot after compared, stopping in case of an error, you would use:
```bash
lpot -t 24 -d 60 -s 300 -p (I don't recommand you to enable -p)
```

## Re-run
If you only want to re-run again.
```bash
lpot -r
```
Then
```bash
configscan -scan
```
And
```bash
lpot -t 24 -d 300 -s 60(Example)
```

## Remove
To remove all lpot program, please notice below two directory and one file.
- Execution Program
```bash
/usr/local/bin
```
- Log Directory
```bash
/lpot
```

- One File
```bash
/etc/systemd/system/lpot_reboot.service
```

All of them must be removed.

## Notes
- Ensure that LPOT has the necessary permissions to perform system reboots.
- Avoid setting delays too short or intervals too frequent, as this might impact system stability.

## Troubleshooting
If LPOT does not behave as expected:
1. Verify that you are using it on a supported operating system.
2. Check for any error messages printed in the terminal during execution.
3. Ensure all command-line arguments are correctly specified according to the usage guide.

## Verion
v1.0: Official Release
v1.1: Fixed an issue where the program would stop due to exceeding the Capabilities area.
v1.2: Standardized the logging system across programs to address inconsistencies and corrected error display and handling methods. Enhace configscan some functions.
     **configscan will fix many times in the future.
v1.3: Configscan fix again.
v1.4: Fix Configscan to avoid timer impact.(Need fix for other network adapters, so it will fix many times)
      Enhaced Configscan to add ignore_bits.txt to avoid timers impact.
      Fix systemd to /lpot/reboot.sh due to change setting without systemd reload
      Fix lpotscan error log cannot write into reboot.log issue
v1.5: Fix lpotscan log will append in reboot.log more times.[lpot]
      Add configscan_log.sh to analyze configscan log and record into reboot.log[lpot]
      Fix install.sh to correct configscan_log.sh location
      Fix lpotscan wrong codec on yaml process
      Add -s to determind wait driver ready time.[lpot]
v1.6: Fix stability and buff overflow issue and optimization signal process, etc. on lpot.c
      Enhance config space scan tool
      Fix lpotscan bugs and remove unused module
      Enhance configscan and lpotscan on ignore bits
      Add lpotscan -scan to check system USB device to ignore parameter.
      Fix above issue again(#20250801)
      Add "-r" to clear lpot

For further assistance, contact the software support team provided by your vendor.

---

Feel free to adjust this documentation as needed to fit your specific requirements or additional features of LPOT.
