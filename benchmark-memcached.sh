#!/bin/bash

################################################################################
# Memcached Benchmarking Script
# Automates performance testing of vanilla memcached, memcached-sr, and BMC
################################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Configuration Variables (modify these as needed)
################################################################################

# SSH Configuration
SSH_USER="user"                    # SSH username for server host
SSH_HOST="server-hostname"         # Server hostname for SSH connection

# Network Configuration
IFACE="eth0"                       # Network interface on server host
INTERFACE_IP="192.168.1.1"         # IP address for memcached to bind to
BMC_INTERFACE_NUM="11"             # BMC interface number

# Memcached Configuration
MEMCACHED_PORT="11211"
MEMCACHED_MEMORY="4096"            # Memory in MB

# Memaslap Configuration
MEMASLAP_DURATION="10s"            # Test duration
MEMASLAP_WARMUP="5s"               # Warmup duration
MEMASLAP_THREADS="32"              # Number of memaslap threads
MEMASLAP_CONNECTIONS="128"         # Number of connections

# Thread numbers to test
THREAD_NUMBERS=(1 2 3 4 5 6 7 8 12 16)

# Directory paths on server
VANILLA_MEMCACHED_DIR="~/memcached-1.6.38"
MEMCACHED_SR_DIR="~/bmc-cache/memcached-sr"
BMC_DIR="~/bmc-cache/bmc"

# Output files
RESULTS_CSV="benchmark_results.csv"
GRAPH_OUTPUT="memcached_benchmark.png"

################################################################################
# Helper Functions
################################################################################

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

# Kill any running memcached processes on server
kill_memcached() {
    print_info "Killing any running memcached processes on server..."
    ssh ${SSH_USER}@${SSH_HOST} "sudo pkill memcached || true"
    sleep 2
}

# Check if required tools are installed
check_dependencies() {
    print_header "Checking Dependencies"
    
    # Check for memaslap locally
    if ! command -v memaslap &> /dev/null; then
        print_error "memaslap not found. Please install libmemcached-tools"
        exit 1
    fi
    
    # Check for Python and pip
    if ! command -v python3 &> /dev/null; then
        print_error "python3 not found. Please install Python 3"
        exit 1
    fi
    
    # Install matplotlib and numpy if needed
    print_info "Installing Python dependencies (matplotlib, numpy)..."
    pip3 install --user matplotlib numpy --quiet 2>/dev/null || {
        python3 -m pip install --user matplotlib numpy --quiet
    }
    
    # Check SSH connectivity
    print_info "Testing SSH connection to ${SSH_USER}@${SSH_HOST}..."
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 ${SSH_USER}@${SSH_HOST} "echo 'SSH connection successful'" &> /dev/null; then
        print_error "Cannot connect to server via SSH. Please check SSH keys and connectivity."
        exit 1
    fi
    
    print_info "All dependencies satisfied"
}

# Initialize results CSV file
initialize_results() {
    print_info "Initializing results file: ${RESULTS_CSV}"
    echo "System,Threads,TPS" > ${RESULTS_CSV}
}

# Run memaslap and extract TPS
run_memaslap() {
    local output_file="memaslap_output.tmp"
    
    print_info "Running memaslap..."
    memaslap -s ${INTERFACE_IP}:${MEMCACHED_PORT} \
             -S ${MEMASLAP_WARMUP} \
             -t ${MEMASLAP_DURATION} \
             -T ${MEMASLAP_THREADS} \
             -c ${MEMASLAP_CONNECTIONS} \
             -a --division 1 > ${output_file} 2>&1
    
    # Extract TPS from last 5 lines
    local tps=$(tail -5 ${output_file} | grep -oP 'TPS:\s*\K[0-9]+' | tail -1)
    
    if [ -z "$tps" ]; then
        print_error "Failed to extract TPS from memaslap output"
        cat ${output_file}
        rm -f ${output_file}
        return 1
    fi
    
    rm -f ${output_file}
    echo "$tps"
}

# Mount BPF filesystem (only needed once)
mount_bpf() {
    print_info "Mounting BPF filesystem on server..."
    ssh ${SSH_USER}@${SSH_HOST} "sudo mount -t bpf none /sys/fs/bpf/ 2>/dev/null || true"
}

# Detach BMC TX hook
detach_bmc_hook() {
    print_info "Detaching BMC TX hook..."
    ssh ${SSH_USER}@${SSH_HOST} "
        sudo tc filter del dev ${IFACE} egress 2>/dev/null || true
        sudo tc qdisc del dev ${IFACE} clsact 2>/dev/null || true
        sudo rm -f /sys/fs/bpf/bmc_tx_filter 2>/dev/null || true
    "
}

# Attach BMC TX hook
attach_bmc_hook() {
    print_info "Attaching BMC TX hook..."
    ssh ${SSH_USER}@${SSH_HOST} "
        sudo tc qdisc add dev ${IFACE} clsact
        sudo tc filter add dev ${IFACE} egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
    "
}

################################################################################
# Benchmarking Functions
################################################################################

benchmark_vanilla_memcached() {
    print_header "Benchmarking Vanilla Memcached"
    
    for threads in "${THREAD_NUMBERS[@]}"; do
        print_info "Testing with ${threads} thread(s)..."
        
        # Kill any existing memcached
        kill_memcached
        
        # Start vanilla memcached
        print_info "Starting vanilla memcached with ${threads} thread(s)..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${VANILLA_MEMCACHED_DIR} && ./memcached -U ${MEMCACHED_PORT} -p ${MEMCACHED_PORT} -m ${MEMCACHED_MEMORY} -d -l ${INTERFACE_IP} -t ${threads}"
        
        # Wait for memcached to start
        sleep 3
        
        # Run memaslap and get TPS
        tps=$(run_memaslap)
        
        if [ $? -eq 0 ]; then
            print_info "TPS for ${threads} thread(s): ${tps}"
            echo "Vanilla,${threads},${tps}" >> ${RESULTS_CSV}
        else
            print_warning "Failed to get TPS for ${threads} thread(s)"
        fi
        
        # Kill memcached
        kill_memcached
        sleep 2
    done
}

benchmark_memcached_sr() {
    print_header "Benchmarking Memcached-SR"
    
    for threads in "${THREAD_NUMBERS[@]}"; do
        print_info "Testing with ${threads} thread(s)..."
        
        # Kill any existing memcached
        kill_memcached
        
        # Start memcached-sr
        print_info "Starting memcached-sr with ${threads} thread(s)..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${MEMCACHED_SR_DIR} && ./memcached -U ${MEMCACHED_PORT} -p ${MEMCACHED_PORT} -m ${MEMCACHED_MEMORY} -d -l ${INTERFACE_IP} -t ${threads}"
        
        # Wait for memcached to start
        sleep 3
        
        # Run memaslap and get TPS
        tps=$(run_memaslap)
        
        if [ $? -eq 0 ]; then
            print_info "TPS for ${threads} thread(s): ${tps}"
            echo "Memcached-SR,${threads},${tps}" >> ${RESULTS_CSV}
        else
            print_warning "Failed to get TPS for ${threads} thread(s)"
        fi
        
        # Kill memcached
        kill_memcached
        sleep 2
    done
}

benchmark_bmc() {
    print_header "Benchmarking BMC"
    
    # Mount BPF filesystem (only once)
    mount_bpf
    
    for threads in "${THREAD_NUMBERS[@]}"; do
        print_info "Testing with ${threads} thread(s)..."
        
        # Kill any existing memcached
        kill_memcached
        
        # Detach any existing BMC hooks
        detach_bmc_hook
        sleep 2
        
        # Start memcached-sr
        print_info "Starting memcached-sr with ${threads} thread(s)..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${MEMCACHED_SR_DIR} && ./memcached -U ${MEMCACHED_PORT} -p ${MEMCACHED_PORT} -m ${MEMCACHED_MEMORY} -d -l ${INTERFACE_IP} -t ${threads}"
        
        # Wait for memcached to start
        sleep 3
        
        # Start BMC
        print_info "Starting BMC..."
        ssh ${SSH_USER}@${SSH_HOST} "cd ${BMC_DIR} && sudo ./bmc ${BMC_INTERFACE_NUM} > /dev/null 2>&1 &"
        
        # Wait for BMC to initialize
        sleep 2
        
        # Attach BMC TX hook
        attach_bmc_hook
        sleep 2
        
        # Run memaslap and get TPS
        tps=$(run_memaslap)
        
        if [ $? -eq 0 ]; then
            print_info "TPS for ${threads} thread(s): ${tps}"
            echo "BMC,${threads},${tps}" >> ${RESULTS_CSV}
        else
            print_warning "Failed to get TPS for ${threads} thread(s)"
        fi
        
        # Detach BMC hooks
        detach_bmc_hook
        
        # Kill memcached
        kill_memcached
        sleep 2
    done
    
    # Final cleanup
    detach_bmc_hook
}

################################################################################
# Graph Generation
################################################################################

generate_graph() {
    print_header "Generating Performance Graph"
    
    python3 - <<'PYTHON_SCRIPT'
import matplotlib.pyplot as plt
import numpy as np
import csv
from collections import defaultdict

# Read data from CSV
data = defaultdict(lambda: {'threads': [], 'tps': []})

with open('benchmark_results.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        system = row['System']
        threads = int(row['Threads'])
        tps = float(row['TPS'])
        data[system]['threads'].append(threads)
        data[system]['tps'].append(tps / 1000)  # Convert to 100k units

# Set up the plot
fig, ax = plt.subplots(figsize=(14, 8))

# Define colors for each system
colors = {
    'Vanilla': '#3498db',      # Blue
    'Memcached-SR': '#e74c3c', # Red
    'BMC': '#2ecc71'           # Green
}

# Get all unique thread numbers and sort them
all_threads = sorted(set(data['Vanilla']['threads'] + 
                        data['Memcached-SR']['threads'] + 
                        data['BMC']['threads']))

# Set up bar positions
x = np.arange(len(all_threads))
width = 0.25  # Width of bars

# Plot bars for each system
systems = ['Vanilla', 'Memcached-SR', 'BMC']
for i, system in enumerate(systems):
    if system in data:
        # Create mapping from threads to TPS
        tps_dict = dict(zip(data[system]['threads'], data[system]['tps']))
        # Get TPS values for all thread numbers (0 if not present)
        tps_values = [tps_dict.get(t, 0) for t in all_threads]
        
        # Plot bars
        offset = width * (i - 1)
        bars = ax.bar(x + offset, tps_values, width, 
                     label=system, color=colors[system], alpha=0.8)
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}',
                       ha='center', va='bottom', fontsize=9)

# Customize the plot
ax.set_xlabel('Number of Threads', fontsize=12, fontweight='bold')
ax.set_ylabel('TPS (×100k)', fontsize=12, fontweight='bold')
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

################################################################################
# Main Execution
################################################################################

main() {
    print_header "Memcached Benchmarking Suite"
    
    echo "Configuration:"
    echo "  SSH: ${SSH_USER}@${SSH_HOST}"
    echo "  Interface: ${IFACE}"
    echo "  Interface IP: ${INTERFACE_IP}"
    echo "  Port: ${MEMCACHED_PORT}"
    echo "  Thread numbers: ${THREAD_NUMBERS[@]}"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Initialize results file
    initialize_results
    
    # Run benchmarks
    benchmark_vanilla_memcached
    benchmark_memcached_sr
    benchmark_bmc
    
    # Generate graph
    generate_graph
    
    # Display results location
    print_header "Benchmarking Complete"
    print_info "Results saved to: ${RESULTS_CSV}"
    print_info "Graph saved to: ${GRAPH_OUTPUT}"
    
    # Display summary
    echo ""
    echo "Summary of Results:"
    column -t -s',' ${RESULTS_CSV}
}

# Run main function
main "$@"
