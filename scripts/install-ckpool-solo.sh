#!/bin/bash

# Exit on errors
set -e

# Function to detect distro and set package manager
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    else
        echo "Unsupported distribution. Exiting."
        exit 1
    fi
    case $DISTRO in
        ubuntu|debian)
            PKG_MANAGER="apt"
            INSTALL_CMD="apt install -y"
            UPDATE_CMD="apt update"
            # libcapnp-dev supplies the capnp-rpc pkg-config module the mining
            # IPC shim links against; libsodium-dev is required by Stratum V2.
            PACKAGES="build-essential git autoconf automake libtool pkg-config yasm libzmq3-dev curl screen libevent-dev libssl-dev bsdmainutils python3 gnupg jq libcapnp-dev libsodium-dev"
            ;;
        fedora|centos|rhel)
            PKG_MANAGER="dnf"  # or yum for older CentOS
            INSTALL_CMD="dnf install -y"
            UPDATE_CMD="dnf check-update"
            PACKAGES="gcc gcc-c++ make git autoconf automake libtool pkgconf-pkg-config yasm zeromq-devel curl screen libevent-devel openssl-devel util-linux python3 gnupg2 jq capnproto-devel libsodium-devel"
            ;;
        *)
            echo "Unsupported distribution: $DISTRO. Exiting."
            exit 1
            ;;
    esac
}

# Check if sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root."
    exit 1
fi

# Detect previous installation
PREVIOUS_INSTALL=false
if [ -f /etc/systemd/system/bitcoind.service ] || [ -f /etc/systemd/system/ckpool.service ] || [ -d /opt/ckpool ] || [ -d /etc/ckpool ] || [ -d /var/log/ckpool ] || [ -f /usr/local/bin/wait-for-bitcoind-sync.sh ]; then
    PREVIOUS_INSTALL=true
fi

if $PREVIOUS_INSTALL; then
    read -p "Previous installation detected. Overwrite existing files and services(no blockchain data will be deleted)? (y/N, default: no): " overwrite_answer
    if [[ ! "$overwrite_answer" =~ ^[Yy]$ ]]; then
        echo "Installation aborted."
        exit 0
    fi
    echo "Overwriting previous installation..."
    # Stop and disable services if they exist
    systemctl stop ckpool 2>/dev/null || true
    systemctl stop bitcoind 2>/dev/null || true
    systemctl disable ckpool 2>/dev/null || true
    systemctl disable bitcoind 2>/dev/null || true
    # Keep the SV2 Noise keys. They are the pool's permanent identity: miners
    # pin the authority public key in their connection URL, so regenerating
    # them would force every SV2 miner to be reconfigured.
    SV2_KEY_BACKUP=""
    if ls /etc/ckpool/sv2_*.key >/dev/null 2>&1; then
        SV2_KEY_BACKUP=$(mktemp -d)
        cp -a /etc/ckpool/sv2_*.key "$SV2_KEY_BACKUP"/
        echo "Preserving existing SV2 keys so the pool keeps its authority public key."
    fi
    # Remove old files
    rm -f /etc/systemd/system/ckpool.service /etc/systemd/system/bitcoind.service
    rm -rf /opt/ckpool /etc/ckpool /var/log/ckpool
    rm -f /usr/local/bin/wait-for-bitcoind-sync.sh /usr/local/bin/ckpool-mining-urls.sh
    # Reload systemd
    systemctl daemon-reload
fi

# Main installation
echo "Starting installation of Bitcoin Core v31.1 and CKPool-Solo. This requires sudo privileges."
echo "Warning: Bitcoin Core downloads the whole ~810GB blockchain while syncing no matter what; pruning only limits how much is kept on disk (~15GB by default here). Ensure sufficient disk space and bandwidth."
echo "Important: You cannot mine with CKPool-Solo until the Bitcoin Core blockchain is fully synchronized, which may take days depending on your hardware and network speed."

# Prompt for service user (default to current sudo user)
current_user=${SUDO_USER:-root}
echo "Optionally, choose a user to run Bitcoin Core and CKPool as (instead of $current_user)."
echo "Any existing blockchain data in the user's .bitcoin directory will be used."
read -p "Enter existing username, or 'create' to make a new 'ckpool' user (leave blank for $current_user): " input_user
if [ "$input_user" = "create" ]; then
    useradd -m -s /bin/bash ckpool
    service_user="ckpool"
elif [ -z "$input_user" ]; then
    service_user="$current_user"
else
    if id "$input_user" >/dev/null 2>&1; then
        service_user="$input_user"
    else
        echo "User $input_user does not exist. Exiting."
        exit 1
    fi
fi
if [ "$service_user" != "root" ]; then
    HOME_DIR="/home/$service_user"
else
    HOME_DIR="/root"
fi

# Prompt for max disk space
MIN_PRUNE_MB=550
# A pruned node still keeps the UTXO set and block index, currently ~11 GB and
# growing, so this floor is what pruning cannot go below regardless of prune=.
PRUNED_OVERHEAD_GB=15
echo "Bitcoin blockchain full size is approximately 810 GB as of August 2026."
echo "Pruning is recommended when this node is only used for mining. CKPool needs"
echo "the UTXO set and the current chain tip to build block templates and to verify"
echo "and submit the blocks it solves; none of that requires keeping historical"
echo "blocks, so pruning does not reduce what you can mine or what you are paid."
echo "A pruned node still needs roughly ${PRUNED_OVERHEAD_GB} GB for the UTXO set and block index."
echo "Choose the full chain only if this node will also serve historical blocks to"
echo "other peers or rescan wallets."
read -p "Enter maximum disk space for Bitcoin data in GB (0 for full chain, default: minimum ${MIN_PRUNE_MB}MB pruned): " max_gb
if [ -z "$max_gb" ]; then
    prune_mb=$MIN_PRUNE_MB
    echo "Pruning to the minimum ${MIN_PRUNE_MB} MB of block data."
    prune_line="prune=$prune_mb"
    required_space=$((PRUNED_OVERHEAD_GB + 1))
elif [ "$max_gb" -eq 0 ]; then
    prune_line=""
    required_space=810
else
    prune_mb=$((max_gb * 1024))
    if [ $prune_mb -lt $MIN_PRUNE_MB ]; then
        echo "Minimum prune size is ${MIN_PRUNE_MB} MB. Setting to ${MIN_PRUNE_MB} MB."
        prune_mb=$MIN_PRUNE_MB
    fi
    prune_line="prune=$prune_mb"
    required_space=$((PRUNED_OVERHEAD_GB + (prune_mb + 1023) / 1024))
fi

# Disk space check (add 10% buffer to required_space)
required_space=$((required_space * 110 / 100))
available_space=$(df -k --output=avail "$HOME_DIR" | tail -n 1)
available_space_gb=$((available_space / 1024 / 1024))
if [ "$available_space_gb" -lt "$required_space" ]; then
    echo "Warning: Insufficient disk space. Required: ~${required_space} GB, Available: ${available_space_gb} GB in $HOME_DIR."
    read -p "Continue anyway? (y/N, default: no): " continue_answer
    if [[ ! "$continue_answer" =~ ^[Yy]$ ]]; then
        echo "Installation aborted due to insufficient disk space."
        exit 1
    fi
    echo "Proceeding with installation despite low disk space. This may cause issues."
fi

# Prompt for assumevalid block hash
read -p "To speed up blockchain sync, enter a trusted recent block hash for assumevalid (default: 0000000000000000000081c26d870f8ac4a0217b8c6dab7b63c25f03b3882c52 at block 960804, or 0 to disable): " assumevalid_hash
if [ "$assumevalid_hash" = "0" ]; then
    assumevalid_line=""
    echo "Assumevalid disabled. Full blockchain verification will be performed."
elif [ -n "$assumevalid_hash" ]; then
    echo "Warning: Using assumevalid skips signature verification up to this block, reducing security. Ensure the hash is from a trusted source."
    assumevalid_line="assumevalid=$assumevalid_hash"
else
    assumevalid_line="assumevalid=0000000000000000000081c26d870f8ac4a0217b8c6dab7b63c25f03b3882c52"
fi

# Prompt for donation to CKPool author
read -p "Support CKPool author with a 0.5% donation on mined blocks? (y/N, default: no): " donation_answer
if [[ "$donation_answer" =~ ^[Yy]$ ]]; then
    donation_line='"donation" : 0.5,'
    echo "Donation of 0.5% enabled. Thank you for supporting CKPool development!"
else
    donation_line=""
    echo "Donation disabled. You can enable it later in /etc/ckpool/ckpool.conf."
fi

# Prompt for coinbase signature
read -p "Enter an optional signature string to include in the coinbase of mined blocks (leave blank for none): " btcsig
if [ -n "$btcsig" ]; then
    btcsig_line="\"btcsig\" : \"$btcsig\","
    echo "Coinbase signature '$btcsig' will be included in mined blocks."
else
    btcsig_line=""
    echo "No coinbase signature set. You can add one later in /etc/ckpool/ckpool.conf."
fi

detect_distro
# dnf check-update exits 100 when updates are available, which would trip set -e.
$UPDATE_CMD || true

# Install dependencies (for Bitcoin Core, CKPool build including the mining IPC
# and Stratum V2 support, rpcauth.py, tarball verification, and jq for sync check)
$INSTALL_CMD $PACKAGES

# Enable persistent journald storage
echo "Enabling persistent journal storage for easier log access..."
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true

# Download and verify Bitcoin Core v31.1 tarball
BITCOIN_VERSION="31.1"
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    BITCOIN_TAR="bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz"
elif [ "$ARCH" = "aarch64" ]; then
    BITCOIN_TAR="bitcoin-${BITCOIN_VERSION}-aarch64-linux-gnu.tar.gz"
else
    echo "Unsupported architecture: $ARCH. Exiting."
    exit 1
fi
BASE_URL="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}"
curl -O ${BASE_URL}/${BITCOIN_TAR}
curl -O ${BASE_URL}/SHA256SUMS
curl -O ${BASE_URL}/SHA256SUMS.asc

# Import Bitcoin Core builder GPG keys
git clone https://github.com/bitcoin-core/guix.sigs -b main --depth 1 /tmp/guix.sigs
gpg --import /tmp/guix.sigs/builder-keys/* || true
rm -rf /tmp/guix.sigs

# Verify hash and signature
sha256sum --ignore-missing --check SHA256SUMS || { echo "Hash verification failed. Exiting."; exit 1; }
gpg --verify SHA256SUMS.asc || { echo "Signature verification failed. Exiting."; exit 1; }

# Extract tarball
tar -zxvf ${BITCOIN_TAR}

# Generate rpcauth using included script
cd bitcoin-${BITCOIN_VERSION}
rpc_output=$(python3 ./share/rpcauth/rpcauth.py ckpooluser)
rpcauth_line=$(echo "$rpc_output" | grep '^rpcauth=')
rpc_password=$(echo "$rpc_output" | tail -1 | sed 's/Your password://' | tr -d '[:space:]')
cd ..

cp -r bitcoin-${BITCOIN_VERSION}/bin/* /usr/local/bin/
# The multiprocess node lives in libexec from v31 on, and the bin/bitcoin
# wrapper resolves it relative to its own location as ../libexec/bitcoin-node.
mkdir -p /usr/local/libexec
cp bitcoin-${BITCOIN_VERSION}/libexec/bitcoin-node /usr/local/libexec/
rm -rf bitcoin-${BITCOIN_VERSION} ${BITCOIN_TAR} SHA256SUMS SHA256SUMS.asc

# Calculate dbcache: 25% of total memory in MB, capped at 12000 MB
total_mem=$(free -m | awk '/Mem:/ {print $2}')
dbcache=$((total_mem * 25 / 100))
if [ $dbcache -gt 12000 ]; then
    dbcache=12000
fi

# Set up Bitcoin Core config and datadir
DATADIR="$HOME_DIR/.bitcoin"
IPC_SOCKET="$DATADIR/node.sock"
# Unix socket paths are limited to 107 characters by the kernel; bitcoin-node
# refuses to start rather than truncating, so catch it before installing.
if [ ${#IPC_SOCKET} -gt 107 ]; then
    echo "IPC socket path $IPC_SOCKET exceeds the 107 character Unix socket limit."
    echo "Choose a service user with a shorter home directory. Exiting."
    exit 1
fi
mkdir -p "$DATADIR"
chown -R $service_user:$service_user "$DATADIR"
cat << EOF > "$DATADIR/bitcoin.conf"
$rpcauth_line
server=1
$prune_line
$assumevalid_line
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
ipcbind=unix:$IPC_SOCKET
zmqpubhashblock=tcp://127.0.0.1:28332
blockmaxweight=3900000
checkblocks=6
blockreconstructionextratxn=1000
dbcache=$dbcache
minrelaytxfee=0.000001
blockmintxfee=0.00001
EOF

# Install CKPool-Solo
git clone https://bitbucket.org/ckolivas/ckpool.git /opt/ckpool
chown -R $service_user:$service_user /opt/ckpool
cd /opt/ckpool
# autogen.sh fetches the bundled secp256k1 submodule, which SV2 needs for its
# ellswift/schnorrsig support. --enable-sv2 makes configure fail loudly if the
# SV2 dependencies are missing rather than silently building without it; the
# mining IPC is enabled automatically when capnp-rpc is present.
./autogen.sh
./configure --enable-sv2
make -j$(nproc)
make install

# Set up CKPool config (minimal, per README-SOLOMINING.md)
mkdir -p /etc/ckpool
# Restore the SV2 keys kept from a previous install before ckpool can generate
# new ones on first start.
if [ -n "${SV2_KEY_BACKUP:-}" ]; then
    cp -a "$SV2_KEY_BACKUP"/sv2_*.key /etc/ckpool/
    rm -rf "$SV2_KEY_BACKUP"
fi
# btcd is still required alongside the IPC socket: ckpool uses JSON-RPC to
# validate addresses and as the getblocktemplate fallback whenever the IPC
# template service is not ready. A usable ipcmining socket is on its own enough
# to drive templates and tip notifications. serverurl must be listed explicitly,
# because configuring sv2url would otherwise suppress the default SV1 listener.
cat << EOF > /etc/ckpool/ckpool.conf
{
  $donation_line
  $btcsig_line
  "btcd" : [
    {
      "url" : "127.0.0.1:8332",
      "auth" : "ckpooluser",
      "pass" : "$rpc_password",
      "notify" : true
    }
  ],
  "ipcmining" : "$IPC_SOCKET",
  "serverurl" : [
    "0.0.0.0:3333"
  ],
  "sv2url" : [
    "0.0.0.0:3336"
  ],
  "sv2_authority_key" : "/etc/ckpool/sv2_authority.key",
  "sv2_static_key" : "/etc/ckpool/sv2_static.key",
  "startdiff" : 10000,
  "logdir" : "/var/log/ckpool"
}
EOF
mkdir -p /var/log/ckpool
chown -R $service_user:$service_user /etc/ckpool /var/log/ckpool

# Create wait script for bitcoind sync with block progress
cat << EOF > /usr/local/bin/wait-for-bitcoind-sync.sh
#!/bin/bash

echo "Starting wait for bitcoind sync at \$(date)"
echo "Using config file: $DATADIR/bitcoin.conf"
while true; do
    if ! bitcoin-cli -conf="$DATADIR/bitcoin.conf" -rpcuser=ckpooluser -rpcpassword=$rpc_password getblockchaininfo >/dev/null 2>&1; then
        echo "Waiting for bitcoind to start... at \$(date)"
        sleep 60
        continue
    fi
    info=\$(bitcoin-cli -conf="$DATADIR/bitcoin.conf" -rpcuser=ckpooluser -rpcpassword=$rpc_password getblockchaininfo 2>/dev/null)
    if [ \$? -ne 0 ]; then
        echo "Error querying bitcoind: RPC failure at \$(date)"
        sleep 60
        continue
    fi
    synced=\$(echo "\$info" | jq '.initialblockdownload' 2>/dev/null)
    blocks=\$(echo "\$info" | jq '.blocks' 2>/dev/null)
    headers=\$(echo "\$info" | jq '.headers' 2>/dev/null)
    if [ -z "\$synced" ] || [ -z "\$blocks" ] || [ -z "\$headers" ]; then
        echo "Error parsing bitcoind info at \$(date)"
        sleep 60
        continue
    fi
    if [ "\$synced" = "false" ]; then
        echo "Blockchain synced: \$blocks blocks at \$(date)"
        break
    fi
    if [ "\$blocks" -gt 0 ] && [ "\$headers" -gt 0 ]; then
        progress=\$(echo "scale=2; \$blocks * 100 / \$headers" | bc)
        echo "Syncing: \$blocks/\$headers blocks (\${progress}%) at \$(date)"
    else
        echo "Waiting for bitcoind to start syncing... at \$(date)"
    fi
    sleep 60
done
EOF
chmod +x /usr/local/bin/wait-for-bitcoind-sync.sh
chown $service_user:$service_user /usr/local/bin/wait-for-bitcoind-sync.sh

# Create helper to print the miner-facing addresses. The SV2 authority public
# key is only created when ckpool first starts, so this reads it back from the
# log rather than being baked in at install time.
cat << EOF > /usr/local/bin/ckpool-mining-urls.sh
#!/bin/bash

CKLOG=/var/log/ckpool/ckpool.log
ip=\$(hostname -I 2>/dev/null | awk '{print \$1}')
[ -n "\$ip" ] || ip="[machine IP]"

echo "Stratum V1 mining address: stratum+tcp://\$ip:3333"
echo "  Username: your Bitcoin address   Password: x"
echo
b58=\$(grep -h "SV2 authority URL path" "\$CKLOG" 2>/dev/null | tail -1 | sed 's|.*<host>:<port>/\\([^)]*\\)).*|\\1|')
if [ -n "\$b58" ]; then
    echo "Stratum V2 mining address: stratum2+tcp://\$ip:3336/\$b58"
    echo "  Authority public key: \$b58"
    echo "  Username: your Bitcoin address   Password: x"
else
    echo "Stratum V2 mining address: stratum2+tcp://\$ip:3336/<authority public key>"
    echo "  The authority public key is generated the first time ckpool starts,"
    echo "  which only happens once the blockchain has finished syncing."
    echo "  Re-run ckpool-mining-urls.sh then, or search \$CKLOG for 'SV2 authority'."
fi
EOF
chmod +x /usr/local/bin/ckpool-mining-urls.sh

# Create systemd services
cat << EOF > /etc/systemd/system/bitcoind.service
[Unit]
Description=Bitcoin Core node (multiprocess, mining IPC)
After=network.target

[Service]
User=$service_user
# bitcoin-node rather than bitcoind: only the multiprocess binary implements
# -ipcbind and the Cap'n Proto mining interface ckpool builds templates from.
ExecStart=/usr/local/libexec/bitcoin-node -conf="$DATADIR/bitcoin.conf" -datadir="$DATADIR" -printtoconsole
Restart=always
TimeoutSec=120
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/ckpool.service
[Unit]
Description=CKPool Solo
After=bitcoind.service

[Service]
User=$service_user
ExecStart=/bin/bash -c '/usr/local/bin/wait-for-bitcoind-sync.sh && exec /usr/local/bin/ckpool -B -q -c /etc/ckpool/ckpool.conf'
StandardOutput=journal
StandardError=journal
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bitcoind ckpool
systemctl start bitcoind ckpool

echo "Installation complete! CKPool-Solo is set to start on ports 3333 (Stratum V1) and 3336 (Stratum V2) after blockchain sync."
echo "Bitcoin Core runs as bitcoin-node with its mining IPC socket at $IPC_SOCKET, which CKPool uses for block templates and notifications."
echo "Important: You cannot mine until the Bitcoin Core blockchain is fully synchronized, which may take days."
echo "Check sync progress with:"
echo "  - journalctl -u ckpool -f (block progress until CKPool starts)"
echo "  - journalctl -u bitcoind -f (detailed sync logs)"
echo "  - tail -f $DATADIR/debug.log (detailed sync logs)"
echo "CKPool startup is delayed until sync completes (monitor with: journalctl -u ckpool -f)."
echo
echo "Mining addresses (replace [machine IP] with this machine's address if shown):"
/usr/local/bin/ckpool-mining-urls.sh
echo
echo "Re-run ckpool-mining-urls.sh at any time to print these again."
echo "SV2 miners must supply the authority public key, which is the base58 string at the end of the stratum2 URL. It is stored permanently in /etc/ckpool/sv2_authority.key and is preserved if you re-run this installer, so it does not change."
echo "Monitor logs:"
echo "  - CKPool: tail -f /var/log/ckpool/ckpool.log (full logs) or journalctl -u ckpool -f (block progress, then reduced CKPool logs)"
echo "  - Bitcoin Core: tail -f $DATADIR/debug.log or journalctl -u bitcoind -f"
echo "Edit configs in $DATADIR/bitcoin.conf and /etc/ckpool/ckpool.conf if needed, then restart services with: systemctl restart bitcoind ckpool"
