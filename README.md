# Memcached Benchmarking Script

This script automates performance testing of vanilla memcached, memcached-sr, and BMC across different thread configurations.

## Features

- Automated benchmarking of three systems: Vanilla Memcached, Memcached-SR, and BMC
- Tests with multiple thread counts: 1, 2, 3, 4, 5, 6, 7, 8, 12, 16
- Automatic TPS extraction from memaslap output
- CSV data export
- Automatic graph generation with color-coded bars
- Remote server management via SSH

## Prerequisites

### On Client Host (where you run the script):
- `memaslap` (from libmemcached-tools package)
- `python3` with `pip`
- SSH keys configured for passwordless authentication to server host
- The script will automatically install Python dependencies (matplotlib, numpy)

### On Server Host:
- Vanilla memcached installed in `~/memcached-1.6.38`
- Memcached-SR installed in `~/bmc-cache/memcached-sr/`
- BMC installed in `~/bmc-cache/bmc/`
- `sudo` access for BMC operations
- `tc` (traffic control) tool for BMC hooks

## Configuration

Before running the script, edit the configuration variables at the top of `benchmark_memcached.sh`:

```bash
# SSH Configuration
SSH_USER="user"                    # Your SSH username
SSH_HOST="server-hostname"         # Server hostname or IP for SSH

# Network Configuration
IFACE="eth0"                       # Network interface on server (e.g., eth0, ens33)
INTERFACE_IP="192.168.1.1"         # IP address for memcached to bind to
BMC_INTERFACE_NUM="11"             # BMC interface number

# Memcached Configuration
MEMCACHED_PORT="11211"             # Memcached port
MEMCACHED_MEMORY="4096"            # Memory allocation in MB

# Memaslap Configuration
MEMASLAP_DURATION="10s"            # Test duration
MEMASLAP_WARMUP="5s"               # Warmup duration
MEMASLAP_THREADS="32"              # Number of memaslap threads
MEMASLAP_CONNECTIONS="128"         # Number of connections

# Thread numbers to test
THREAD_NUMBERS=(1 2 3 4 5 6 7 8 12 16)
```

## Usage

1. Make the script executable:
```bash
chmod +x benchmark_memcached.sh
```

2. Edit the configuration variables in the script to match your environment

3. Run the script:
```bash
./benchmark_memcached.sh
```

## Output

The script generates two files:

1. **`benchmark_results.csv`** - Contains all TPS measurements
   - Format: System, Threads, TPS
   - Example:
     ```
     System,Threads,TPS
     Vanilla,1,45231
     Vanilla,2,87654
     ...
     ```

2. **`memcached_benchmark.png`** - Performance graph
   - Bar chart with TPS (in 100k units) on Y-axis
   - Number of threads on X-axis
   - Three color-coded bar groups:
     - Blue: Vanilla Memcached
     - Red: Memcached-SR
     - Green: BMC

## Script Workflow

### For Vanilla Memcached:
1. Kill any existing memcached processes
2. Start vanilla memcached with specified thread count
3. Run memaslap and capture TPS
4. Record results
5. Repeat for each thread count

### For Memcached-SR:
1. Kill any existing memcached processes
2. Start memcached-sr with specified thread count
3. Run memaslap and capture TPS
4. Record results
5. Repeat for each thread count

### For BMC:
1. Mount BPF filesystem (once)
2. For each thread count:
   - Kill existing memcached
   - Detach any existing BMC hooks
   - Start memcached-sr
   - Start BMC
   - Attach BMC TX hooks
   - Run memaslap and capture TPS
   - Record results
   - Detach BMC hooks
3. Final cleanup of BMC hooks

## Troubleshooting

### SSH Connection Issues
- Ensure SSH keys are properly configured: `ssh-copy-id user@server-hostname`
- Test connection manually: `ssh user@server-hostname "echo test"`

### Memaslap Not Found
- Install libmemcached-tools:
  - Ubuntu/Debian: `sudo apt-get install libmemcached-tools`
  - CentOS/RHEL: `sudo yum install libmemcached`

### BMC Hook Issues
- Ensure you have sudo privileges on the server
- Check if `tc` tool is installed: `which tc`
- Verify network interface name is correct

### No TPS Captured
- Check that memcached is actually running: `ssh user@server "ps aux | grep memcached"`
- Verify IP addresses and ports are correct
- Test memaslap connection manually: `memaslap -s IP:11211 -t 5s`

### Python Graph Generation Fails
- Ensure Python 3 is installed: `python3 --version`
- Manually install dependencies: `pip3 install matplotlib numpy`

## Customization

### Changing Thread Numbers
Edit the `THREAD_NUMBERS` array in the script:
```bash
THREAD_NUMBERS=(1 2 4 8 16 32)  # Custom thread counts
```

### Changing Test Duration
Modify the memaslap configuration:
```bash
MEMASLAP_DURATION="30s"  # Longer test duration
MEMASLAP_WARMUP="10s"    # Longer warmup
```

### Different Directory Paths
Update the directory variables:
```bash
VANILLA_MEMCACHED_DIR="~/custom/path/to/memcached"
MEMCACHED_SR_DIR="~/custom/path/to/memcached-sr"
BMC_DIR="~/custom/path/to/bmc"
```

## Script Features

- **Automatic Cleanup**: Kills memcached processes between tests
- **Error Handling**: Exits on critical errors, warns on minor issues
- **Color-Coded Output**: Easy-to-read terminal output
- **Dependency Checking**: Verifies all required tools before starting
- **Progress Tracking**: Shows current test progress
- **Results Summary**: Displays final results in tabular format

## Notes

- The script uses `set -e` to exit on errors
- BMC hooks are automatically cleaned up after testing
- All TPS values are extracted from the last 5 lines of memaslap output
- Graph shows TPS in 100k units for better readability
- The script waits 2-3 seconds between operations to ensure clean state

## Example Output

```
================================
Memcached Benchmarking Suite
================================
Configuration:
  SSH: user@server-hostname
  Interface: eth0
  Interface IP: 192.168.1.1
  Port: 11211
  Thread numbers: 1 2 3 4 5 6 7 8 12 16

[INFO] All dependencies satisfied
[INFO] Initializing results file: benchmark_results.csv

================================
Benchmarking Vanilla Memcached
================================
[INFO] Testing with 1 thread(s)...
[INFO] Starting vanilla memcached with 1 thread(s)...
[INFO] Running memaslap...
[INFO] TPS for 1 thread(s): 45231
...

================================
Benchmarking Complete
================================
[INFO] Results saved to: benchmark_results.csv
[INFO] Graph saved to: memcached_benchmark.png

Summary of Results:
System         Threads  TPS
Vanilla        1        45231
Vanilla        2        87654
...
```

## License

This script is provided as-is for benchmarking purposes.
