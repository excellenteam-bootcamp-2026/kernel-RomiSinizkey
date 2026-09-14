# Linux Kernel Firewall

## Overview

This is a Linux kernel firewall being developed incrementally, starting
from a minimal loadable kernel module and growing into a working IPv4
packet filter. The current implementation uses Linux **Netfilter** to
inspect incoming IPv4 traffic and apply source/destination address
filtering directly inside the kernel.

The project has progressed through the following stages:

```text
Basic loadable Linux kernel module
        |
        v
Kernel build / load / unload workflow
        |
        v
Network investigation (system calls, kernel logging)
        |
        v
Linux Netfilter integration
        |
        v
PRE_ROUTING hook
        |
        v
IPv4 packet inspection
        |
        v
Source IPv4 filtering
        |
        v
Destination IPv4 filtering
        |
        v
Independent source/destination block lists + rate-limited logging
        |
        v
Future: dynamic rule integration from user space
```

## Current Capabilities

* Loadable Linux kernel module (`insmod` / `rmmod`)
* Linux Netfilter integration
* A `NF_INET_PRE_ROUTING` hook that inspects every incoming IPv4 packet
* IPv4 header inspection (`saddr` / `daddr`)
* Source IPv4 filtering against a configurable block list
* Destination IPv4 filtering against a configurable block list
* Separate, independently-checked source and destination block lists
  backed by one shared lookup helper
* `NF_DROP` / `NF_ACCEPT` filtering decisions
* Rate-limited kernel logging (`pr_info_ratelimited`) when a packet is
  dropped, for both source and destination matches

## Architecture / Packet Flow

```text
Incoming IPv4 packet
        |
        v
Linux Netfilter
        |
        v
PRE_ROUTING
        |
        v
firewall_hook_fn()
        |
        v
IPv4 header
        |
        v
Source block list?
   yes -> NF_DROP
        |
        no
        v
Destination block list?
   yes -> NF_DROP
        |
        no
        v
NF_ACCEPT
```

## Netfilter

Netfilter is the packet-filtering framework built into the Linux kernel.
It lets kernel code register "hooks" — callback functions — that run at
specific points in the kernel's IPv4 packet-processing path. This project
uses Netfilter because it is the standard, supported way to inspect and
make allow/drop decisions on packets from inside the kernel, without
modifying the core networking stack itself.

The module registers a single hook at `NF_INET_PRE_ROUTING`
(`kernel/firewall_module.c`, `firewall_init`):

```c
firewall_hook.hook = firewall_hook_fn;
firewall_hook.pf = NFPROTO_IPV4;
firewall_hook.hooknum = NF_INET_PRE_ROUTING;
firewall_hook.priority = NF_IP_PRI_FIRST;
```

`NF_INET_PRE_ROUTING` fires for every incoming IPv4 packet as soon as it
arrives at the network stack, before the kernel decides how to route it
(e.g. to a local socket or onward). This makes it a natural place to drop
unwanted packets as early as possible.

## IPv4 Filtering

`firewall_hook_fn` retrieves the IPv4 header from the packet with
`ip_hdr(skb)` and reads:

* `saddr` — the source IPv4 address
* `daddr` — the destination IPv4 address

The function defensively checks for a missing socket buffer (`!skb`) and a
missing/unparsed IP header (`!ip_header`) and returns `NF_ACCEPT` in either
case rather than dereferencing a null pointer.

An incoming packet is dropped when:

* its source address (`saddr`) appears in the blocked-sources list, or
* its destination address (`daddr`) appears in the blocked-destinations
  list.

At module load time, `firewall_init` initializes these lists with example
addresses:

```c
blocked_sources[0] = in_aton("8.8.8.8");
blocked_sources[1] = in_aton("1.1.1.1");
blocked_sources_count = 2;

blocked_destinations[0] = in_aton("10.0.2.15");
blocked_destinations_count = 1;
```

Filtering decision, in order:

```text
saddr matches blocked_sources      -> NF_DROP
daddr matches blocked_destinations -> NF_DROP
no match on either list            -> NF_ACCEPT
```

## Block Lists

Filtering is built on two independent, fixed-size arrays
(`MAX_BLOCKED_IPS` = 32 entries each):

* `blocked_sources` / `blocked_sources_count`
* `blocked_destinations` / `blocked_destinations_count`

Each `*_count` variable tracks how many entries in the corresponding array
are currently in use, since the arrays themselves are fixed-size and not
all slots are necessarily populated.

Both lists are searched using one shared helper, `is_ip_in_list()`, which
performs a linear scan of `count` entries in `list` looking for `ip`. Two
thin wrappers call it for each list so the call sites read clearly:

* `is_blocked_source(ip)` → `is_ip_in_list(ip, blocked_sources, blocked_sources_count)`
* `is_blocked_destination(ip)` → `is_ip_in_list(ip, blocked_destinations, blocked_destinations_count)`

Because each list is checked only up to its `*_count`, a list with a count
of `0` is naturally treated as empty — `is_ip_in_list()` never enters its
loop and returns `false` — so no address is dropped based on that list.
There is no dynamic add/remove logic; an "empty list" here simply means the
corresponding `*_count` was left at (or set to) `0`.

## Logging

When `firewall_hook_fn` drops a packet, it logs the decision with
`pr_info_ratelimited`:

```text
firewall_module: dropping packet from <source IPv4>
firewall_module: dropping packet to <destination IPv4>
```

Rate-limiting is used because packet processing can happen very frequently
(a busy or actively-blocked flow can generate many matching packets per
second) — unrestricted kernel logging on every dropped packet could flood
`dmesg` and degrade the system. The module also logs its lifecycle:

```text
firewall_module: loaded
Hello World
firewall_module: failed to register Netfilter hook   (only on registration failure)
firewall_module: unloaded
```

## Environment

This module is built and tested inside a disposable **Ubuntu** virtual
machine (e.g. run with **VirtualBox**), never directly on the host machine,
since kernel code runs with full kernel privileges and a bug can crash the VM.

Required inside the VM:

* Matching **Linux kernel headers** for the currently running kernel
* `build-essential` (compiler and build tools)
* `git`
* The **Kbuild** system (part of the kernel headers package), used to build
  the module against the running kernel's build tree

Example setup:

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
uname -r
```

## Repository Structure

```text
.
├── kernel/
│   ├── firewall_module.c
│   └── Makefile
├── .gitignore
└── README.md
```

`kernel/firewall_module.c` and `kernel/Makefile` are the only files needed
to build the module. Everything else Kbuild generates during a build
(`.o`, `.ko`, `.mod`, `.mod.c`, `.cmd` files, `Module.symvers`,
`modules.order`) is a build artifact and is excluded from version control —
see [`.gitignore`](.gitignore).

## Building

From inside the Ubuntu VM:

```bash
cd kernel
make clean
make
```

This uses the Kbuild system to compile the module against the currently
running kernel's build directory and produces `firewall_module.ko`, the
loadable kernel object.

`make clean` removes all files generated by a previous build (`.o`, `.ko`,
`.mod`, `.mod.c`, `.cmd` files, `Module.symvers`, `modules.order`).

Before loading, you can inspect the module's metadata:

```bash
ls -l firewall_module.ko
modinfo firewall_module.ko
```

This shows fields such as the module name, author, description, license,
and the `vermagic` string (the kernel version/config the module was built
against — it must match the running kernel).

## Loading and Unloading

Load the module:

```bash
sudo insmod firewall_module.ko
```

Verify it's loaded:

```bash
lsmod | grep firewall_module
```

View module logs:

```bash
sudo dmesg | grep firewall_module
```

To watch kernel messages live while testing (e.g. while pinging blocked and
allowed addresses in another terminal):

```bash
sudo dmesg -w
```

Unload the module:

```bash
sudo rmmod firewall_module
sudo dmesg | grep firewall_module
```

Always unload the module before ending a test session — do not leave it
loaded.

### Development cycle

Editing `firewall_module.c` does not change a module that is already loaded
into the kernel — the running module keeps executing its previously loaded
code until it is explicitly unloaded and replaced. After every source
change:

```text
Edit source
 -> unload old module   (sudo rmmod firewall_module)
 -> make clean
 -> make
 -> insmod firewall_module.ko
 -> verify with dmesg / lsmod
```

## Testing / Verification

Filtering was exercised with IPv4 `ping` traffic against the addresses
hardcoded in `firewall_init`. Observed behavior:

* **Blocked source (`8.8.8.8`)** — pings to `8.8.8.8` showed 100% packet
  loss while the module was loaded with it present in `blocked_sources`.
* **Blocked source (`1.1.1.1`)** — same result: 100% packet loss while
  blocked.
* **Multiple source entries** — both `8.8.8.8` and `1.1.1.1` were blocked
  simultaneously, confirming the source list is checked as a set, not just
  a single hardcoded address.
* **Unblocked source (`8.8.4.4`)** — reachable (normal ping replies) when
  it was not present in `blocked_sources` and `blocked_destinations` was
  empty, confirming unmatched traffic falls through to `NF_ACCEPT`.
* **Blocked destination (`10.0.2.15`)** — traffic to this address showed
  packet loss while it was present in `blocked_destinations`.
* **Independent source/destination checks** — clearing one list (setting
  its `*_count` to `0`) while keeping the other populated confirmed that
  each list is evaluated independently of the other.
* **Empty source list** — with `blocked_sources_count` at `0`, no source
  address was dropped, regardless of its value.
* **Empty destination list** — with `blocked_destinations_count` at `0`, no
  destination address was dropped, regardless of its value.
* **Module removal** — after `sudo rmmod firewall_module`, previously
  blocked addresses became reachable again, confirming the hook is fully
  unregistered on unload and normal connectivity is restored.

Kernel logs during these tests included lines such as:

```text
firewall_module: dropping packet from 8.8.8.8
firewall_module: dropping packet to 10.0.2.15
```

## Current Limitations

* The entries in `blocked_sources` and `blocked_destinations` are
  **hardcoded inside `firewall_init`** and only take effect when the module
  is built and loaded. There is no runtime API (procfs, sysfs, ioctl,
  netlink, etc.) to add or remove addresses from a running module.
* The block lists are **not** loaded from PostgreSQL or any other database.
* The kernel module does **not** connect to a database and is **not**
  synchronized with any larger firewall application — it is fully
  self-contained.
* Filtering is stateless and address-based only: there is no port,
  protocol, or connection-state matching.

## Future Direction

The broader firewall system is expected to eventually include
application/user-space components, with the long-term goal of firewall
rules reaching this kernel module dynamically instead of being hardcoded.
At a high level, the intended direction looks like:

```text
Firewall application / database
        |
        v
User-space component
        |
        v
Kernel communication mechanism
        |
        v
Kernel rule lists
        |
        v
Netfilter filtering
```

This integration is **not** implemented yet. No specific kernel/user-space
communication mechanism (e.g. netlink, procfs, sysfs, ioctl) has been
chosen or implemented, and the database does not communicate with the
kernel directly — any future data path would run through a user-space
component.

**Current:** `blocked_sources` and `blocked_destinations` are populated by
hardcoded initialization in `firewall_init`.
**Future:** these lists would be updated dynamically, driven from user
space.

## Safety

Kernel modules execute with full kernel privileges — a bug can freeze or
crash the entire operating system, not just a single process. All building,
loading, and unloading is done inside a **disposable Ubuntu VM**, never on
the host machine, and a VM snapshot is taken before loading the module for
the first time so the VM can be restored if it becomes unstable or
unbootable.

## Deployment: Automatic Startup (Project 12, Task 7)

The kernel module and `firewall-agent` can be installed so both survive a
VM reboot with no manual `insmod` or manual agent launch. All deployment
files live under [`deploy/`](deploy/):

```text
deploy/
├── systemd/firewall-agent.service   # systemd unit for the agent
├── modules-load.d/firewall.conf     # tells systemd to modprobe the module at boot
├── firewall-agent.env.example       # template for FIREWALL_API_URL (not installed automatically)
└── install.sh                       # copies everything into place
```

### Build

```bash
cd kernel && make && cd ..
cd firewall-agent && make && cd ..
```

### Install

```bash
sudo bash deploy/install.sh
```

This copies `firewall_module.ko` into `/lib/modules/$(uname -r)/extra/`,
runs `depmod -a` so `modprobe` can resolve it, installs
`/etc/modules-load.d/firewall.conf` (automatic module load at boot),
installs the `firewall-agent` binary to `/usr/local/bin/`, installs the
systemd unit, and runs `systemctl enable firewall-agent`. It does **not**
start the service automatically — see "Configuring FIREWALL_API_URL" below
for why.

### Configuring `FIREWALL_API_URL`

The service reads `FIREWALL_API_URL` from `/etc/default/firewall-agent`
(a plain `KEY=value` file, loaded via the unit's `EnvironmentFile=`
directive) rather than from a value baked into the `.service` file or the
source code. This keeps the systemd unit itself reusable across
environments — a dev VM, a different VM, or a real deployment — without
editing tracked files or committing an environment-specific address.

```bash
sudo cp deploy/firewall-agent.env.example /etc/default/firewall-agent
sudo nano /etc/default/firewall-agent   # uncomment and set FIREWALL_API_URL
```

For the current development setup (Node.js running on the Windows host,
VM using VirtualBox NAT networking):

```
FIREWALL_API_URL=http://10.0.2.2:3000/api/firewall/rules?type=ip
```

`/etc/default/firewall-agent` is not tracked in git — only the `.example`
template is.

### Verifying module auto-load

```bash
sudo modprobe firewall_module      # manual check without waiting for a reboot
lsmod | grep firewall_module
sudo dmesg | grep firewall_module
```

### Controlling the service

```bash
sudo systemctl start firewall-agent
sudo systemctl status firewall-agent
sudo systemctl stop firewall-agent
sudo systemctl restart firewall-agent
sudo journalctl -u firewall-agent -f
```

### Reboot verification

```bash
sudo reboot
# after the VM comes back up, with no manual commands:
lsmod | grep firewall_module          # module auto-loaded
sudo systemctl status firewall-agent  # active (running), started automatically
```

## Appendix: Exploring System Calls with `strace`

As part of investigating how user-space programs interact with the kernel,
`strace` was used to trace a simple command:

```bash
strace -o trace.txt ls
```

Three system calls selected from the trace and their purpose:

* **`openat`** — opens a file or directory (here, the directory being
  listed) and returns a file descriptor used by subsequent calls.
* **`getdents64`** — reads directory entries from an open directory file
  descriptor; this is how `ls` retrieves the list of file names to display.
* **`write`** — writes data (the formatted directory listing) from the
  process to a file descriptor, typically standard output, so the result is
  printed to the terminal.

**Why `strace` shows system calls and not C library functions:**
`strace` works by tracing the interactions between a user-space process and
the Linux kernel, not the internal workings of a process. Programs commonly
call C library functions (e.g. `printf`), which run entirely in user space
and internally invoke one or more system calls to actually get privileged
work done (e.g. `printf` may eventually call `write`). Since `strace`
observes the user-space/kernel boundary, it reports the underlying system
calls such as `openat`, `getdents64`, and `write`, rather than the
higher-level library functions that triggered them.
