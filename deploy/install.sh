#!/usr/bin/env bash
# Installs the firewall kernel module and firewall-agent as a systemd
# service on Ubuntu, so both survive a reboot without manual insmod /
# manual agent launches (Project 12, Task 7).
#
# Run this from inside the Ubuntu VM, after building both components:
#   cd kernel && make && cd ../firewall-agent && make && cd ..
#   sudo bash deploy/install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

KERNEL_MODULE="$REPO_ROOT/kernel/firewall_module.ko"
AGENT_BINARY="$REPO_ROOT/firewall-agent/firewall-agent"
MODULE_DIR="/lib/modules/$(uname -r)/extra"

echo "==> Checking build artifacts"
if [ ! -f "$KERNEL_MODULE" ]; then
    echo "error: $KERNEL_MODULE not found - run 'make' in kernel/ first" >&2
    exit 1
fi
if [ ! -f "$AGENT_BINARY" ]; then
    echo "error: $AGENT_BINARY not found - run 'make' in firewall-agent/ first" >&2
    exit 1
fi

# The running agent process keeps its executable open, so overwriting
# /usr/local/bin/firewall-agent in place while it's running fails with
# "Text file busy". Stop it first if needed, and remember to put it back
# the way we found it once the new files are in place.
WAS_RUNNING=false
HANDLED=false

if systemctl is-active --quiet firewall-agent; then
    WAS_RUNNING=true
fi

# Safety net: if this script fails or is interrupted after stopping the
# service but before the normal restart step below runs, don't leave a
# previously-running agent stopped.
restore_on_exit() {
    local exit_code=$?
    if [ "$WAS_RUNNING" = true ] && [ "$HANDLED" = false ] && ! systemctl is-active --quiet firewall-agent; then
        echo "==> install interrupted before firewall-agent could be restarted - attempting to restart it" >&2
        if systemctl start firewall-agent; then
            echo "==> firewall-agent restarted" >&2
        else
            echo "error: firewall-agent could not be restarted - run 'sudo systemctl start firewall-agent' manually" >&2
        fi
    fi
    exit "$exit_code"
}
trap restore_on_exit EXIT

if [ "$WAS_RUNNING" = true ]; then
    echo "==> firewall-agent is currently running - stopping it before replacing the binary"
    systemctl stop firewall-agent
fi

echo "==> Installing kernel module to $MODULE_DIR"
mkdir -p "$MODULE_DIR"
cp "$KERNEL_MODULE" "$MODULE_DIR/"
depmod -a

echo "==> Configuring automatic module load (modules-load.d)"
cp "$SCRIPT_DIR/modules-load.d/firewall.conf" /etc/modules-load.d/firewall.conf

echo "==> Installing firewall-agent binary to /usr/local/bin"
cp "$AGENT_BINARY" /usr/local/bin/firewall-agent

echo "==> Installing systemd unit"
cp "$SCRIPT_DIR/systemd/firewall-agent.service" /etc/systemd/system/firewall-agent.service
systemctl daemon-reload
systemctl enable firewall-agent

if [ "$WAS_RUNNING" = true ]; then
    echo "==> Restarting firewall-agent (it was running before this install)"
    if systemctl start firewall-agent && systemctl is-active --quiet firewall-agent; then
        HANDLED=true
        echo "==> firewall-agent restarted successfully"
    else
        HANDLED=true
        echo "error: firewall-agent did not come back up after install - check 'systemctl status firewall-agent' and 'journalctl -u firewall-agent'" >&2
        exit 1
    fi

    cat <<'EOF'

==> Install complete. firewall-agent.service was already running and has
been restarted with the new binary/unit. It remains enabled for future
boots.
EOF
else
    cat <<'EOF'

==> Install complete.

firewall-agent.service is ENABLED (it will auto-start on future boots) but
has NOT been started yet, and FIREWALL_API_URL is not configured yet.

Before starting it for the first time on this machine:

  1. Set the Node.js API URL for this environment, e.g.:
       sudo cp deploy/firewall-agent.env.example /etc/default/firewall-agent
       sudo nano /etc/default/firewall-agent   # uncomment and set FIREWALL_API_URL

  2. Load the kernel module now (or reboot to test auto-load via modules-load.d):
       sudo modprobe firewall_module
       lsmod | grep firewall_module

  3. Start the agent:
       sudo systemctl start firewall-agent
       sudo systemctl status firewall-agent
       sudo journalctl -u firewall-agent -f
EOF
fi
