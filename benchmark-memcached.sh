#!/bin/bash

################################################################################
# Memcached Benchmarking Script
# Automates performance testing of vanilla memcached, memcached-sr, and BMC
################################################################################

set -e  #exit on error

#color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' #no color

#configuration variables (modify these as needed)

#SSH configuration
SSH_USER="user"                    #SSH username for server host
SSH_HOST="server-hostname"         #server hostname for SSH connection
SSH_PASS="your_password"           #sudo password for server host (leave empty if passwordless sudo)

#network configuration
IFACE="eth0"                       #network interface on server host
INTERFACE_IP="192.168.1.1"         #IP address for memcached to bind to
BMC_INTERFACE_NUM="11"             #BMC interface number

#memcached configuration
MEMCACHED_PORT="11211"
MEMCACHED_MEMORY="4096"            #memory in MB

#memaslap configuration
MEMASLAP_DURATION="10s"            #test duration
MEMASLAP_WARMUP="5s"               #warmup duration
MEMASLAP_THREADS="32"              #number of memaslap threads
MEMASLAP_CONNECTIONS="128"         #number of connections

#thread numbers to test
THREAD_NUMBERS=(1 2 3 4 5 6 7 8 12 16)

#directory paths on server
VANILLA_MEMCACHED_DIR="~/memcached-1.6.38"
MEMCACHED_SR_DIR="~/bmc-cache/memcached-sr"
BMC_DIR="~/bmc-cache/bmc"

#output files
RESULTS_CSV="benchmark_results.csv"
GRAPH_OUTPUT="memcached_benchmark.png"

#helper functions

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

#kill any running memcached processes on server
#parameters:
#  $1 - "silent" to suppress output, empty for normal output
kill_memcached() {
    local silent=$1
    
    if [ "$silent" != "silent" ]; then
        print_info "Killing any running memcached processes on server..."
    fi
    
    if [ -z "$SSH_PASS" ]; then
        ssh ${SSH_USER}@${SSH_HOST} "sudo pkill memcached || true" 2>/dev/null
    else
        ssh ${SSH_USER}@${SSH_HOST} "echo '${SSH_PASS}' | sudo -S pkill memcached || true" 2>/dev/null
    fi
    sleep 2
}

#kill any running BMC processes on server
#parameters:
#  $1 - "silent" to suppress output, empty for normal output
kill_bmc() {
    local silent=$1
    
    if [ "$silent" != "silent" ]; then
        print_info "Killing any running BMC processes on server..."
    fi
    
    if [ -z "$SSH_PASS" ]; then
        ssh ${SSH_USER}@${SSH_HOST} "sudo pkill -9 bmc || true" 2>/dev/null
    else
        ssh ${SSH_USER}@${SSH_HOST} "echo '${SSH_PASS}' | sudo -S pkill -9 bmc || true" 2>/dev/null
    fi
    sleep 1
}

#check if required tools are installed
check_dependencies() {
    print_header "Checking Dependencies"
    
    #check for memaslap locally
    if ! command -v memaslap &> /dev/null; then
        print_error "memaslap not found. Please install libmemcached-tools"
        exit 1
    fi
    
    #check for Python and pip
    if ! command -v python3 &> /dev/null; then
        print_error "python3 not found. Please install Python 3"
        exit 1
    fi
    
    #install matplotlib and numpy if needed
    print_info "Installing Python dependencies (matplotlib, numpy)..."
    pip3 install --user matplotlib numpy --quiet 2>/dev/null || {
        python3 -m pip install --user matplotlib numpy --quiet
    }
    
    #check SSH connectivity
    print_info "Testing SSH connection to ${SSH_USER}@${SSH_HOST}..."
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 ${SSH_USER}@${SSH_HOST} "echo 'SSH connection successful'" &> /dev/null; then
        print_error "Cannot connect to server via SSH. Please check SSH keys and connectivity."
        exit 1
    fi
    
    print_info "All dependencies satisfied"
}

#initialize results CSV file
initialize_results() {
    print_info "Initializing results file: ${RESULTS_CSV}"
    echo "System,Threads,TPS" > ${RESULTS_CSV}
}

#run memaslap and extract TPS
run_memaslap() {
    local output_file="memaslap_output.tmp"
    
    #run memaslap and capture only its output (print to console separately)
    print_info "Running memaslap..." >&2
    
    memaslap -s ${INTERFACE_IP}:${MEMCACHED_PORT} \
             -S ${MEMASLAP_WARMUP} \
             -t ${MEMASLAP_DURATION} \
             -T ${MEMASLAP_THREADS} \
             -c ${MEMASLAP_CONNECTIONS} \
             -a --division 1 > ${output_file} 2>&1
    
    #extract TPS from last 5 lines
    local tps=$(tail -5 ${output_file} | grep -oP 'TPS:\s*\K[0-9]+' | tail -1)
    
    if [ -z "$tps" ]; then
        print_error "Failed to extract TPS from memaslap output" >&2
        echo "===== Memaslap output debug =====" >&2
        cat ${output_file} >&2
        echo "=================================" >&2
        rm -f ${output_file}
        return 1
    fi
    
    rm -f ${output_file}
    echo "$tps"
}

#mount BPF filesystem (only needed once)
mount_bpf() {
    print_info "Mounting BPF filesystem on server..."
    if [ -z "$SSH_PASS" ]; then
        ssh ${SSH_USER}@${SSH_HOST} "sudo mount -t bpf none /sys/fs/bpf/ 2>/dev/null || true"
    else
        ssh ${SSH_USER}@${SSH_HOST} "echo '${SSH_PASS}' | sudo -S mount -t bpf none /sys/fs/bpf/ 2>/dev/null || true"
    fi
}

#detach BMC TX hook
detach_bmc_hook() {
    print_info "Detaching BMC TX hook..."
    if [ -z "$SSH_PASS" ]; then
        ssh ${SSH_USER}@${SSH_HOST} "
            sudo tc filter del dev ${IFACE} egress 2>/dev/null || true
            sudo tc qdisc del dev ${IFACE} clsact 2>/dev/null || true
            sudo rm -f /sys/fs/bpf/bmc_tx_filter 2>/dev/null || true
        "
    else
        ssh ${SSH_USER}@${SSH_HOST} "
            echo '${SSH_PASS}' | sudo -S tc filter del dev ${IFACE} egress 2>/dev/null || true
            echo '${SSH_PASS}' | sudo -S tc qdisc del dev ${IFACE} clsact 2>/dev/null || true
            echo '${SSH_PASS}' | sudo -S rm -f /sys/fs/bpf/bmc_tx_filter 2>/dev/null || true
        "
    fi
}

#attach BMC TX hook
attach_bmc_hook() {
    print_info "Attaching BMC TX hook..."
    if [ -z "$SSH_PASS" ]; then
        ssh ${SSH_USER}@${SSH_HOST} "
            sudo tc qdisc add dev ${IFACE} clsact
            sudo tc filter add dev ${IFACE} egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
        "
    else
        ssh ${SSH_USER}@${SSH_HOST} "
            echo '${SSH_PASS}' | sudo -S tc qdisc add dev ${IFACE} clsact
            echo '${SSH_PASS}' | sudo -S tc filter add dev ${IFACE} egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
        "
    fi
}

#benchmarking functions

benchmark_vanilla_memcached() {
    print_header "Benchmarking Vanilla Memcached"
    
    for threads in "${THREAD_NUMBERS[@]}"; do
        print_info "Testing with ${threads} thread(s)..."
        
        #kill any existing memcached (silent)
        kill_memcached "silent"
        
        #start vanilla memcached
        print_info "Starting vanilla memcached with ${threads} thread(s)..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${VANILLA_MEMCACHED_DIR} && ./memcached -U ${MEMCACHED_PORT} -p ${MEMCACHED_PORT} -m ${MEMCACHED_MEMORY} -d -l ${INTERFACE_IP} -t ${threads}"
        
        #wait for memcached to start
        sleep 3
        
        #run memaslap and get TPS
        tps=$(run_memaslap)
        
        if [ $? -eq 0 ]; then
            print_info "TPS for ${threads} thread(s): ${tps}"
            echo "Vanilla,${threads},${tps}" >> ${RESULTS_CSV}
        else
            print_warning "Failed to get TPS for ${threads} thread(s)"
        fi
        
        #kill memcached (with output)
        kill_memcached
    done
}

benchmark_memcached_sr() {
    print_header "Benchmarking Memcached-SR"
    
    for threads in "${THREAD_NUMBERS[@]}"; do
        print_info "Testing with ${threads} thread(s)..."
        
        #kill any existing memcached (silent)
        kill_memcached "silent"
        
        #start memcached-sr
        print_info "Starting memcached-sr with ${threads} thread(s)..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${MEMCACHED_SR_DIR} && ./memcached -U ${MEMCACHED_PORT} -p ${MEMCACHED_PORT} -m ${MEMCACHED_MEMORY} -d -l ${INTERFACE_IP} -t ${threads}"
        
        #wait for memcached to start
        sleep 3
        
        #run memaslap and get TPS
        tps=$(run_memaslap)
        
        if [ $? -eq 0 ]; then
            print_info "TPS for ${threads} thread(s): ${tps}"
            echo "Memcached-SR,${threads},${tps}" >> ${RESULTS_CSV}
        else
            print_warning "Failed to get TPS for ${threads} thread(s)"
        fi
        
        #kill memcached (with output)
        kill_memcached
    done
}

benchmark_bmc() {
    print_header "Benchmarking BMC"
    
    #mount BPF filesystem (only once)
    mount_bpf
    
    for threads in "${THREAD_NUMBERS[@]}"; do
        print_info "Testing with ${threads} thread(s)..."
        
        #kill any existing memcached (silent)
        kill_memcached "silent"
        
        #kill any existing BMC processes (silent)
        kill_bmc "silent"
        
        #detach any existing BMC hooks
        detach_bmc_hook
        sleep 2
        
        #start memcached-sr
        print_info "Starting memcached-sr with ${threads} thread(s)..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${MEMCACHED_SR_DIR} && ./memcached -U ${MEMCACHED_PORT} -p ${MEMCACHED_PORT} -m ${MEMCACHED_MEMORY} -d -l ${INTERFACE_IP} -t ${threads}"
        
        #wait for memcached to start
        sleep 3
        
        #start BMC
        print_info "Starting BMC..."
        if [ -z "$SSH_PASS" ]; then
            ssh -f ${SSH_USER}@${SSH_HOST} "cd ${BMC_DIR} && sudo ./bmc ${BMC_INTERFACE_NUM} > /dev/null 2>&1"
        else
            ssh -f ${SSH_USER}@${SSH_HOST} "cd ${BMC_DIR} && echo '${SSH_PASS}' | sudo -S ./bmc ${BMC_INTERFACE_NUM} > /dev/null 2>&1"
        fi
        
        #wait for BMC to initialize
        sleep 2
        
        #attach BMC TX hook
        attach_bmc_hook
        sleep 2
        
        #run memaslap and get TPS
        tps=$(run_memaslap)
        
        if [ $? -eq 0 ]; then
            print_info "TPS for ${threads} thread(s): ${tps}"
            echo "BMC,${threads},${tps}" >> ${RESULTS_CSV}
        else
            print_warning "Failed to get TPS for ${threads} thread(s)"
        fi
        
        #detach BMC hooks
        detach_bmc_hook
        
        #kill BMC (with output)
        kill_bmc
        
        #kill memcached (with output)
        kill_memcached
    done
    
    #final cleanup
    detach_bmc_hook
    kill_bmc "silent"
}

#graph generation

generate_graph() {
    print_header "Generating Performance Graph"
    
    python3 - <<'PYTHON_SCRIPT'
import matplotlib.pyplot as plt
import numpy as np
import csv
import re
from collections import defaultdict

# Function to strip ANSI color codes
def strip_ansi(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

# Function to extract numeric value from string (handles multiline)
def extract_number(text):
    # Strip ANSI codes first
    text = strip_ansi(text).strip()
    # Extract all digits (handles cases where number might be on next line)
    numbers = re.findall(r'\d+', text)
    if numbers:
        # Return the last/largest number found (usually the TPS value)
        return numbers[-1]
    return None

# Read data from CSV
data = defaultdict(lambda: {'threads': [], 'tps': []})

with open('benchmark_results.csv', 'r') as f:
    content = f.read()
    
# Parse CSV more carefully, handling multiline values
lines = content.strip().split('\n')
header_found = False

for i, line in enumerate(lines):
    if not header_found:
        if 'System' in line and 'Threads' in line and 'TPS' in line:
            header_found = True
        continue
    
    # Skip empty lines
    if not line.strip():
        continue
    
    # Parse the line
    parts = line.split(',')
    
    if len(parts) >= 3:
        system = strip_ansi(parts[0]).strip()
        threads_str = strip_ansi(parts[1]).strip()
        tps_str = strip_ansi(parts[2]).strip()
        
        # Check if TPS might be on the next line
        if not tps_str.replace('.','').replace('-','').isdigit() and i + 1 < len(lines):
            # TPS is likely on the next line
            next_line = lines[i + 1].strip()
            tps_extracted = extract_number(next_line)
            if tps_extracted:
                tps_str = tps_extracted
        
        # Extract numbers from fields
        threads_num = extract_number(threads_str)
        tps_num = extract_number(tps_str)
        
        # Validate we have valid data
        if system and threads_num and tps_num:
            try:
                threads = int(threads_num)
                tps = float(tps_num)
                data[system]['threads'].append(threads)
                data[system]['tps'].append(tps / 1000000)  # Convert to Mop/s (millions of operations per second)
            except (ValueError, TypeError):
                continue

# Check if we have any data
if not data:
    print("ERROR: No valid data found in CSV file")
    exit(1)

# Set up the plot
fig, ax = plt.subplots(figsize=(14, 8))

# Define colors for each system
colors = {
    'Vanilla': '#3498db',      # Blue
    'Memcached-SR': '#e74c3c', # Red
    'BMC': '#2ecc71'           # Green
}

# Get all unique thread numbers and sort them
all_threads = sorted(set(data.get('Vanilla', {}).get('threads', []) + 
                        data.get('Memcached-SR', {}).get('threads', []) + 
                        data.get('BMC', {}).get('threads', [])))

if not all_threads:
    print("ERROR: No thread data found")
    exit(1)

# Set up bar positions
x = np.arange(len(all_threads))
width = 0.25  # Width of bars

# Plot bars for each system
systems = ['Vanilla', 'Memcached-SR', 'BMC']
for i, system in enumerate(systems):
    if system in data and data[system]['threads']:
        # Create mapping from threads to TPS
        tps_dict = dict(zip(data[system]['threads'], data[system]['tps']))
        # Get TPS values for all thread numbers (0 if not present)
        tps_values = [tps_dict.get(t, 0) for t in all_threads]
        
        # Plot bars
        offset = width * (i - 1)
        bars = ax.bar(x + offset, tps_values, width, 
                     label=system, color=colors[system], alpha=0.8)

# Customize the plot
ax.set_xlabel('Number of Threads', fontsize=12, fontweight='bold')
ax.set_ylabel('TPS (Mop/s)', fontsize=12, fontweight='bold')
ax.set_title('Memcached Performance Benchmark: TPS vs Thread Count', 
            fontsize=14, fontweight='bold', pad=20)
ax.set_xticks(x)
ax.set_xticklabels(all_threads)
ax.legend(fontsize=11, loc='upper left')
ax.grid(axis='y', alpha=0.3, linestyle='--')

# Add some padding to y-axis
ymin, ymax = ax.get_ylim()
ax.set_ylim(0, ymax * 1.1)

# Tight layout
plt.tight_layout()

# Save the figure
plt.savefig('memcached_benchmark.png', dpi=300, bbox_inches='tight')
print("Graph saved as: memcached_benchmark.png")
plt.close()
PYTHON_SCRIPT

    if [ $? -eq 0 ]; then
        print_info "Graph generated successfully: ${GRAPH_OUTPUT}"
    else
        print_error "Failed to generate graph"
    fi
}

#main execution

main() {
    print_header "Memcached Benchmarking Suite"
    
    echo "Configuration:"
    echo "  SSH: ${SSH_USER}@${SSH_HOST}"
    echo "  Interface: ${IFACE}"
    echo "  Interface IP: ${INTERFACE_IP}"
    echo "  Port: ${MEMCACHED_PORT}"
    echo "  Thread numbers: ${THREAD_NUMBERS[@]}"
    echo ""
    
    #check dependencies
    check_dependencies
    
    #initialize results file
    initialize_results
    
    #run benchmarks
    benchmark_vanilla_memcached
    benchmark_memcached_sr
    benchmark_bmc
    
    #generate graph
    generate_graph
    
    #display results location
    print_header "Benchmarking Complete"
    print_info "Results saved to: ${RESULTS_CSV}"
    print_info "Graph saved to: ${GRAPH_OUTPUT}"
    
    #display summary
    echo ""
    echo "Summary of Results:"
    column -t -s',' ${RESULTS_CSV}
}
#run main function
main "$@"
