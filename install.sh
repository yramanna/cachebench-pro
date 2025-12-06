#!/bin/bash

###############################################################################
# Memcached Stack Installation Script
# Installs: memcached, memcached-sr, and bmc
# Usage: 
#   Local:  ./install.sh
#   Remote: ./install.sh user@remote-host [options]
###############################################################################

set -e  #exit on any error

#color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' #no color

#configuration
MEMCACHED_VER=1.6.38
CLANG_VER=9.0.0
WORK_DIR="$HOME/memcached-install"
LOG_FILE="$WORK_DIR/install.log"

#helper functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

usage() {
    cat << EOF
Usage: $0 [user@remote-host] [OPTIONS]

Run locally (installs memaslap and dpdk client only):
  $0

Run on remote host (installs memcached stack on remote, memaslap/dpdk locally):
  $0 user@remote-host [-i key] [-p port]

Options:
  -i, --identity FILE    SSH private key file
  -p, --port PORT        SSH port (default: 22)
  -h, --help             Show this help message

Examples:
  $0                                    #install memaslap and dpdk client locally
  $0 ubuntu@192.168.1.100               #install memcached stack on remote host
  $0 user@host -i ~/.ssh/key -p 2222    #remote with SSH key and custom port

Note: When remote host is specified, memaslap and dpdk client are installed
      locally, while memcached, bmc, and memcached-sr are installed remotely.
EOF
    exit 0
}

#remote execution logic
execute_remote() {
    local REMOTE_HOST="$1"
    local SSH_KEY="$2"
    local SSH_PORT="$3"
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Remote Installation Mode${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo "Target: $REMOTE_HOST"
    echo "Port: $SSH_PORT"
    echo ""
    
    #test SSH connection
    echo -e "${YELLOW}Testing SSH connection...${NC}"
    if ! ssh $SSH_KEY -p "$SSH_PORT" -o ConnectTimeout=10 -o BatchMode=yes "$REMOTE_HOST" "echo 'OK'" 2>/dev/null; then
        echo -e "${RED}Error: Cannot connect to $REMOTE_HOST${NC}"
        echo "Check: network, credentials, and SSH keys"
        exit 1
    fi
    echo -e "${GREEN}Connection successful${NC}"
    echo ""
    
    #copy this script to remote host
    echo -e "${YELLOW}Copying script to remote host...${NC}"
    REMOTE_SCRIPT="/tmp/install_memcached_$(date +%s).sh"
    scp $SSH_KEY -P "$SSH_PORT" "$0" "$REMOTE_HOST:$REMOTE_SCRIPT" || error "Failed to copy script"
    
    #execute on remote host (no arguments = local mode)
    echo -e "${GREEN}Executing installation on remote host...${NC}"
    echo ""
    ssh $SSH_KEY -p "$SSH_PORT" -t "$REMOTE_HOST" "bash $REMOTE_SCRIPT --remote-server" || error "Remote installation failed"
    
    #cleanup
    ssh $SSH_KEY -p "$SSH_PORT" "$REMOTE_HOST" "rm -f $REMOTE_SCRIPT"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Remote installation completed!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Remember to run on the remote host:${NC}"
    echo -e "  ${GREEN}source ~/.bashrc${NC}"
    exit 0
}

#parse arguments
REMOTE_HOST=""
SSH_KEY=""
SSH_PORT=22
REMOTE_SERVER_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -i|--identity)
            SSH_KEY="-i $2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        --remote-server)
            REMOTE_SERVER_MODE=true
            shift
            ;;
        -*)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            usage
            ;;
        *)
            if [ -z "$REMOTE_HOST" ]; then
                REMOTE_HOST="$1"
            else
                echo -e "${RED}Error: Unexpected argument '$1'${NC}"
                usage
            fi
            shift
            ;;
    esac
done

#install local tools (memaslap and dpdk client)
if [ -n "$REMOTE_HOST" ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Installing Local Tools${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    #create working directory for logs
    mkdir -p "$WORK_DIR"
    
    #install and configure memaslap locally
    log "Installing memaslap locally..."
    
    #install build dependencies for memaslap
    sudo apt update || warn "Failed to update package lists"
    sudo apt install -y build-essential libc6-dev libevent-dev flex bison cmake || error "Failed to install memaslap dependencies"
    
    cd "$HOME"
    if [ -d "$HOME/libmemcached" ]; then
        warn "libmemcached directory already exists, skipping clone"
        cd "$HOME/libmemcached"
        git pull || warn "Failed to update libmemcached repository"
    else
        git clone git@github.com:aagontuk/libmemcached || error "Failed to clone libmemcached. Ensure SSH keys are configured for GitHub."
        cd "$HOME/libmemcached"
    fi
    
    mkdir -p build
    cd build
    cmake .. || error "Failed to configure libmemcached"
    make || error "Failed to build libmemcached"
    sudo make install || error "Failed to install libmemcached"
    
    log "Creating memaslap configuration file..."
    MEMASLAP_CONFIG="$HOME/.memaslap.cnf"
    cat > "$MEMASLAP_CONFIG" << 'EOF'
key
16 16 1
value
16 16 1
cmd
0 0.05
1 0.95
zipf
0.99
EOF
    
    log "Memaslap configuration saved to $MEMASLAP_CONFIG"
    
    #install dpdk client locally
    log "Installing DPDK client (dmemslap) locally..."
    
    #install DPDK first
    log "Installing DPDK..."
    sudo apt install -y dpdk dpdk-dev libdpdk-dev || error "Failed to install DPDK"
    
    cd "$HOME"
    if [ -d "$HOME/dmemslap" ]; then
        warn "dmemslap directory already exists, skipping installation"
    else
        #cleanup any partial smartkv clone
        rm -rf smartkv
        git clone --no-checkout git@github.com:utah-scs/smartkv.git || error "Failed to clone smartkv repository"
        cd smartkv
        git sparse-checkout init --cone || error "Failed to initialize sparse checkout"
        git sparse-checkout set dmemslap || error "Failed to set sparse checkout path"
        git checkout main || error "Failed to checkout main branch"
        
        cd dmemslap
        export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/
        make || error "Failed to build dmemslap"
        
        cd "$HOME"
        mv smartkv/dmemslap ./dmemslap || error "Failed to move dmemslap directory"
        rm -rf smartkv || warn "Failed to remove smartkv temporary directory"
        
        log "DPDK client (dmemslap) installed successfully"
    fi
    
    echo ""
    log "Local tools installation completed"
    log "  - Memaslap: $HOME/libmemcached/build"
    log "  - Memaslap config: $HOME/.memaslap.cnf"
    log "  - DPDK client (dmemslap): $HOME/dmemslap"
    echo ""
fi

#if remote host specified, execute remotely
if [ -n "$REMOTE_HOST" ]; then
    execute_remote "$REMOTE_HOST" "$SSH_KEY" "$SSH_PORT"
fi

#determine installation mode
if [ "$REMOTE_SERVER_MODE" = true ]; then
    #remote server installation (memcached stack)
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Remote Server Installation Mode${NC}"
    echo -e "${GREEN}Installing memcached stack${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    #create working directory
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    log "Starting remote server installation..."
    log "Working directory: $WORK_DIR"
    
    #install system dependencies
    log "Step 1: Installing system dependencies..."
    sudo apt update || error "Failed to update package lists"
    sudo apt upgrade -y || warn "Some packages failed to upgrade"
    sudo apt install -y \
        libevent-dev \
        gpg \
        curl \
        tar \
        xz-utils \
        make \
        gcc \
        flex \
        bison \
        libssl-dev \
        libelf-dev \
        automake \
        libz3-dev \
        git \
        wget || error "Failed to install system dependencies"
    
    log "System dependencies installed successfully"
    
    #install memcached from source
    log "Step 2: Installing memcached ${MEMCACHED_VER}..."
    
    if [ -f "/usr/local/bin/memcached" ]; then
        warn "Memcached already installed at /usr/local/bin/memcached"
    else
        wget "https://memcached.org/files/memcached-${MEMCACHED_VER}.tar.gz" || error "Failed to download memcached"
        tar -zxvf "memcached-${MEMCACHED_VER}.tar.gz" || error "Failed to extract memcached"
        cd "memcached-${MEMCACHED_VER}"
        ./configure || error "Memcached configure failed"
        make || error "Memcached build failed"
        sudo make install || error "Memcached installation failed"
        cd "$WORK_DIR"
        log "Memcached ${MEMCACHED_VER} installed successfully"
    fi
    
    #install llvm/clang 9.0.0
    log "Step 3: Installing LLVM/Clang ${CLANG_VER}..."
    
    if [ -d "/usr/local/clang_9.0.0" ]; then
        warn "Clang 9.0.0 already installed at /usr/local/clang_9.0.0"
    else
        wget "http://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-pc-linux-gnu.tar.xz" || error "Failed to download Clang"
        tar -xJvf "clang+llvm-9.0.0-x86_64-pc-linux-gnu.tar.xz" || error "Failed to extract Clang"
        sudo mv "clang+llvm-9.0.0-x86_64-pc-linux-gnu" "/usr/local/clang_9.0.0" || error "Failed to move Clang to /usr/local"
        log "Clang ${CLANG_VER} installed successfully"
    fi
    
    #update PATH and LD_LIBRARY_PATH
    BASHRC="$HOME/.bashrc"
    if ! grep -q "clang_9.0.0" "$BASHRC"; then
        log "Adding Clang to PATH in .bashrc"
        echo '' >> "$BASHRC"
        echo '# Clang 9.0.0 paths' >> "$BASHRC"
        echo 'export PATH=/usr/local/clang_9.0.0/bin:$PATH' >> "$BASHRC"
        echo 'export LD_LIBRARY_PATH=/usr/local/clang_9.0.0/lib:$LD_LIBRARY_PATH' >> "$BASHRC"
    else
        warn "Clang paths already in .bashrc"
    fi
    
    #export for current session
    export PATH=/usr/local/clang_9.0.0/bin:$PATH
    export LD_LIBRARY_PATH=/usr/local/clang_9.0.0/lib:$LD_LIBRARY_PATH
    
    #create symlinks
    if [ ! -f "/usr/lib/libz3.so.4.8" ]; then
        log "Creating libz3 symlink"
        sudo ln -sf /usr/lib/x86_64-linux-gnu/libz3.so.4 /usr/lib/libz3.so.4.8 || warn "Failed to create libz3 symlink"
    fi
    
    if [ ! -f "/usr/local/clang_9.0.0/bin/llc-9" ]; then
        log "Creating llc-9 symlink"
        sudo ln -sf /usr/local/clang_9.0.0/bin/llc /usr/local/clang_9.0.0/bin/llc-9 || warn "Failed to create llc-9 symlink"
    fi
    
    #clone and build bmc-cache
    log "Step 4: Cloning bmc-cache repository..."
    
    cd "$HOME"
    if [ -d "$HOME/bmc-cache" ]; then
        warn "bmc-cache directory already exists, skipping clone"
        cd "$HOME/bmc-cache"
        git pull || warn "Failed to update bmc-cache repository"
    else
        git clone git@github.com:aagontuk/bmc-cache || error "Failed to clone bmc-cache. Ensure SSH keys are configured for GitHub."
        cd "$HOME/bmc-cache"
    fi
    
    log "Downloading kernel source..."
    ./kernel-src-download.sh || error "Failed to download kernel source"
    
    log "Preparing kernel source..."
    ./kernel-src-prepare.sh || error "Failed to prepare kernel source"
    
    log "Building bmc..."
    cd bmc
    make || error "Failed to build bmc"
    cd ..
    
    #build memcached-sr
    log "Step 5: Building memcached-sr..."
    
    cd "$HOME/bmc-cache/memcached-sr"
    ./autogen.sh || error "Failed to run autogen.sh"
    
    CC=clang-9 CFLAGS='-DREUSEPORT_OPT=1 -Wno-deprecated-declarations' ./configure || error "Failed to configure memcached-sr"
    make || error "Failed to build memcached-sr"
    
    #completion
    log "=========================================="
    log "Remote server installation completed!"
    log "=========================================="
    log ""
    log "Installation summary:"
    log "  - Memcached ${MEMCACHED_VER}: /usr/local/bin/memcached"
    log "  - Clang ${CLANG_VER}: /usr/local/clang_9.0.0"
    log "  - BMC: $HOME/bmc-cache/bmc"
    log "  - Memcached-SR: $HOME/bmc-cache/memcached-sr"
    log ""
    log "IMPORTANT: Run the following command to update your environment:"
    log "  ${YELLOW}source $HOME/.bashrc${NC}"
    log ""
    log "Or log out and log back in for changes to take effect."
    log ""
    log "Installation log: $LOG_FILE"
else
    #local-only installation (memaslap and dpdk client)
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Local-Only Installation Mode${NC}"
    echo -e "${GREEN}Installing memaslap and DPDK client${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    #create working directory
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    log "Starting local tools installation..."
    
    #install and configure memaslap locally
    log "Step 1: Installing memaslap..."
    
    #install build dependencies for memaslap
    sudo apt update || warn "Failed to update package lists"
    sudo apt install -y build-essential libc6-dev libevent-dev flex bison cmake || error "Failed to install memaslap dependencies"
    
    cd "$HOME"
    if [ -d "$HOME/libmemcached" ]; then
        warn "libmemcached directory already exists, skipping clone"
        cd "$HOME/libmemcached"
        git pull || warn "Failed to update libmemcached repository"
    else
        git clone git@github.com:aagontuk/libmemcached || error "Failed to clone libmemcached. Ensure SSH keys are configured for GitHub."
        cd "$HOME/libmemcached"
    fi
    
    mkdir -p build
    cd build
    cmake .. || error "Failed to configure libmemcached"
    make || error "Failed to build libmemcached"
    sudo make install || error "Failed to install libmemcached"
    
    log "Creating memaslap configuration file..."
    MEMASLAP_CONFIG="$HOME/.memaslap.cnf"
    cat > "$MEMASLAP_CONFIG" << 'EOF'
key
16 16 1
value
16 16 1
cmd
0 0.05
1 0.95
zipf
0.99
EOF
    
    log "Memaslap configuration saved to $MEMASLAP_CONFIG"
    
    #install dpdk client locally
    log "Step 2: Installing DPDK client (dmemslap)..."
    
    #install DPDK first
    log "Installing DPDK..."
    sudo apt install -y dpdk dpdk-dev libdpdk-dev || error "Failed to install DPDK"
    
    cd "$HOME"
    if [ -d "$HOME/dmemslap" ]; then
        warn "dmemslap directory already exists, skipping installation"
    else
        #cleanup any partial smartkv clone
        rm -rf smartkv
        git clone --no-checkout git@github.com:utah-scs/smartkv.git || error "Failed to clone smartkv repository"
        cd smartkv
        git sparse-checkout init --cone || error "Failed to initialize sparse checkout"
        git sparse-checkout set dmemslap || error "Failed to set sparse checkout path"
        git checkout main || error "Failed to checkout main branch"
        
        cd dmemslap
        export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig/
        make || error "Failed to build dmemslap"
        
        cd "$HOME"
        mv smartkv/dmemslap ./dmemslap || error "Failed to move dmemslap directory"
        rm -rf smartkv || warn "Failed to remove smartkv temporary directory"
        
        log "DPDK client (dmemslap) installed successfully"
    fi
    
    #completion
    log "=========================================="
    log "Local tools installation completed!"
    log "=========================================="
    log ""
    log "Installation summary:"
    log "  - Memaslap: $HOME/libmemcached/build"
    log "  - Memaslap config: $HOME/.memaslap.cnf"
    log "  - DPDK client (dmemslap): $HOME/dmemslap"
    log ""
    log "Installation log: $LOG_FILE"
fi
exit 0
