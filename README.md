# eBPF-Based Intelligent Cloud Infrastructure Observability, Security & Auto-Remediation Platform

An intelligent infrastructure monitoring platform that uses **eBPF, Linux kernel observability, Kubernetes, event correlation, anomaly detection, root-cause analysis, and controlled auto-remediation** to detect and respond to infrastructure-level problems.

---

## Overview

Modern cloud-native applications run across multiple layers including applications, containers, Kubernetes workloads, Linux processes, networking, and the operating system kernel.

Traditional monitoring tools often provide metrics and logs but may not provide enough visibility into low-level system behavior.

This project uses **eBPF (Extended Berkeley Packet Filter)** to observe Linux kernel events with low overhead and combines those events with Kubernetes and infrastructure telemetry.

The platform is designed to:

* Monitor Linux kernel and process activity
* Observe network and system-level events
* Correlate events across infrastructure layers
* Detect abnormal behavior
* Identify probable root causes
* Generate actionable recommendations
* Perform controlled and policy-based remediation
* Provide centralized infrastructure visibility through dashboards

---

## Objectives

The primary objectives of the project are:

1. Build kernel-level observability using eBPF.
2. Monitor process, system-call, network, and file-system activity.
3. Correlate low-level events with Kubernetes workloads.
4. Detect infrastructure and security anomalies.
5. Build a root-cause analysis engine.
6. Generate remediation recommendations.
7. Support controlled automated remediation.
8. Provide centralized monitoring through Prometheus and Grafana.
9. Support multi-node Kubernetes environments.
10. Provide incident timelines and replay capabilities.

---

## System Architecture

```text
                         CLOUD / KUBERNETES CLUSTER
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
           Node 1               Node 2               Node 3
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  │
                                  ▼
                           ┌─────────────┐
                           │    eBPF     │
                           │  Collector  │
                           └──────┬──────┘
                                  │
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
          Process Events     Network Events    File/Syscall
                                                   Events
                │                 │                 │
                └─────────────────┼─────────────────┘
                                  ▼
                         EVENT CORRELATION
                                  │
                 ┌────────────────┼────────────────┐
                 │                │                │
                 ▼                ▼                ▼
            Performance       Security          Network
             Analyzer          Engine           Analyzer
                 │                │                │
                 └────────────────┼────────────────┘
                                  ▼
                         ANOMALY DETECTION
                                  │
                                  ▼
                         ROOT-CAUSE ENGINE
                                  │
                                  ▼
                         DECISION ENGINE
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             Recommendation             Auto-Remediation
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                         Kubernetes / Cloud
                                  │
                                  ▼
                       Prometheus + Grafana
                                  │
                                  ▼
                            Web Dashboard
```

---

## Core Features

### 1. eBPF Kernel Observability

The platform collects low-level Linux events using eBPF.

Planned event sources include:

* Process execution
* Process creation and termination
* System calls
* Network activity
* TCP events
* File-system activity
* Scheduler activity
* Resource behavior

---

### 2. Event Correlation

Events from different infrastructure layers are correlated to identify relationships between system behavior and application performance.

Example:

```text
Kubernetes Pod
      ↓
Container
      ↓
Process
      ↓
Network Connection
      ↓
Network Retransmissions
      ↓
Application Latency
      ↓
Service Degradation
```

---

### 3. Anomaly Detection

The platform will establish workload-specific baselines and identify unusual behavior.

Planned techniques include:

* Statistical thresholds
* Moving averages
* Z-score based detection
* Isolation Forest
* Time-series analysis

The system will focus on explainable infrastructure anomalies rather than using machine learning unnecessarily.

---

### 4. Security Monitoring

The security engine will identify suspicious infrastructure behavior such as:

* Unexpected process execution
* Unusual network connections
* Unexpected file activity
* Suspicious container behavior
* Abnormal system-call patterns

Detected events will be converted into security incidents with supporting evidence.

---

### 5. Root-Cause Analysis

The root-cause engine will correlate events and identify the most relevant contributing events.

Example:

```text
CPU Spike
   ↓
Process Activity Increased
   ↓
Container Resource Usage Increased
   ↓
Pod Performance Degraded
   ↓
Application Latency Increased
```

The system will provide a probable cause together with supporting events and confidence information.

---

### 6. Controlled Auto-Remediation

The platform will support policy-based remediation.

Examples:

* Restart a non-critical test workload
* Restart a failed Kubernetes pod
* Apply predefined Kubernetes actions
* Generate remediation recommendations

Automated actions will be restricted to explicitly defined and safe policies.

---

### 7. Infrastructure Dashboard

The dashboard will provide views for:

* Infrastructure overview
* Node health
* Kubernetes workloads
* Process activity
* Network activity
* Security events
* Detected anomalies
* Incidents
* Root-cause analysis
* Remediation actions
* Incident timeline and replay

---

## Technology Stack

| Category                | Technology            |
| ----------------------- | --------------------- |
| Operating System        | Linux                 |
| Kernel Observability    | eBPF                  |
| eBPF Language           | C                     |
| eBPF Framework          | libbpf                |
| eBPF Portability        | CO-RE                 |
| Kernel Type Information | BTF                   |
| Backend                 | Python / FastAPI      |
| Monitoring              | Prometheus            |
| Visualization           | Grafana               |
| Containers              | Docker                |
| Orchestration           | Kubernetes            |
| Anomaly Detection       | Python / Scikit-learn |
| Version Control         | Git / GitHub          |
| Development             | VS Code / Linux Shell |

---

## Project Structure

```text
ebpf-infrastructure-intelligence/
│
├── ebpf/
│   ├── vmlinux.h
│   │
│   ├── process/
│   │   ├── process_monitor.bpf.c
│   │   ├── process_monitor.bpf.o
│   │   ├── process_monitor.skel.h
│   │   ├── process_monitor.c
│   │   └── process_monitor
│   │
│   ├── syscall/
│   ├── network/
│   ├── filesystem/
│   └── scheduler/
│
├── collector/
│   ├── event_pipeline/
│   ├── parsers/
│   └── exporters/
│
├── correlation/
│   ├── event_correlator/
│   ├── dependency_graph/
│   └── incident_builder/
│
├── analytics/
│   ├── performance/
│   ├── network/
│   ├── security/
│   └── anomaly_detection/
│
├── root_cause/
│   ├── rules/
│   └── analyzer/
│
├── remediation/
│   ├── policies/
│   ├── recommendations/
│   └── kubernetes_actions/
│
├── backend/
│   ├── api/
│   ├── models/
│   ├── services/
│   └── main.py
│
├── kubernetes/
│   ├── daemonset/
│   ├── deployment/
│   ├── services/
│   └── monitoring/
│
├── dashboard/
│
├── tests/
├── benchmarks/
├── docs/
├── scripts/
│
├── Dockerfile
├── docker-compose.yml
├── README.md
└── LICENSE
```

> The project structure will grow incrementally as each subsystem is implemented.

---

## Current Implementation Status

### Phase 1 — eBPF Development Environment

* [x] WSL2 Linux environment
* [x] Ubuntu development environment
* [x] Clang installation
* [x] libbpf installation
* [x] bpftool installation
* [x] BTF availability verified
* [x] eBPF kernel capabilities verified
* [x] Git repository initialized
* [x] GitHub repository created

### Phase 2 — Process Monitoring

* [x] Generate `vmlinux.h`
* [x] Create CO-RE eBPF program
* [x] Compile eBPF object
* [x] Generate libbpf skeleton
* [x] Create userspace loader
* [x] Load eBPF program into kernel
* [x] Capture process execution events
* [x] Read events through ring buffer
* [x] Display process events in userspace

### Upcoming Phases

* [ ] Enhanced process metadata
* [ ] System-call monitoring
* [ ] Network event monitoring
* [ ] File-system monitoring
* [ ] Prometheus metrics
* [ ] Kubernetes integration
* [ ] Security detection engine
* [ ] Anomaly detection
* [ ] Event correlation
* [ ] Root-cause analysis
* [ ] Recommendation engine
* [ ] Controlled auto-remediation
* [ ] Multi-node Kubernetes deployment
* [ ] Grafana dashboard
* [ ] Incident replay
* [ ] Performance benchmarking
* [ ] Testing and documentation

---

## Development Workflow

The project follows an incremental engineering workflow:

```text
Learn
  ↓
Design
  ↓
Implement
  ↓
Test
  ↓
Measure
  ↓
Document
  ↓
Commit
  ↓
Push
```

Each major feature is developed, tested, documented, and committed independently.

---

## Current eBPF Process Monitor

The first implemented component monitors the Linux `sched_process_exec` tracepoint.

```text
Process Execution
       ↓
sched_process_exec
       ↓
eBPF Program
       ↓
Ring Buffer
       ↓
libbpf Userspace Loader
       ↓
Process Event
       ↓
Terminal
```

Example output:

```text
eBPF process monitor started.
Monitoring process execution events...

Process executed | PID: 2922 | Command: ls
Process executed | PID: 2933 | Command: date
Process executed | PID: 2937 | Command: sed
```

---

## Installation

### Prerequisites

* Linux / WSL2
* Clang
* LLVM
* libbpf
* bpftool
* Git
* Kernel BTF support
* Root privileges for loading eBPF programs

### Environment Setup

```bash
sudo apt update

sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    bpftool \
    git \
    curl
```

Verify:

```bash
clang --version
bpftool version
git --version
```

Check BTF:

```bash
ls -lh /sys/kernel/btf/vmlinux
```

---

## Building the Process Monitor

Generate kernel type information:

```bash
sudo bpftool btf dump \
    file /sys/kernel/btf/vmlinux \
    format c > ebpf/vmlinux.h
```

Compile the eBPF program:

```bash
clang -O2 -g \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I./ebpf \
    -c ebpf/process/process_monitor.bpf.c \
    -o ebpf/process/process_monitor.bpf.o
```

Generate the libbpf skeleton:

```bash
bpftool gen skeleton \
    ebpf/process/process_monitor.bpf.o \
    > ebpf/process/process_monitor.skel.h
```

Compile the userspace loader:

```bash
clang -O2 -g \
    -I./ebpf/process \
    -I./ebpf \
    ebpf/process/process_monitor.c \
    -o ebpf/process/process_monitor \
    -lbpf
```

Run:

```bash
sudo ./ebpf/process/process_monitor
```

---

## Security Considerations

The project is designed with controlled infrastructure automation in mind.

Automated remediation will:

* Use explicitly defined policies
* Restrict actions to approved operations
* Maintain an incident/action record
* Separate recommendation mode from automated mode
* Avoid arbitrary command execution

---

## Future Scope

Future development may include:

* Advanced Kubernetes workload correlation
* Distributed tracing integration
* eBPF-based network visibility
* Service dependency graphs
* Advanced anomaly detection
* Automated incident classification
* Policy-driven remediation
* Multi-node cluster support
* Performance benchmarking
* Historical incident analysis
* Infrastructure behavior profiling

---

## Project Status

**Current milestone:** Process-level eBPF observability implemented successfully.

The platform is currently under active development, with additional observability, analytics, security, Kubernetes, and remediation components planned.

---

## Author

**M N Monisha**

Computer Science Engineering
RV Institute of Technology and Management, Bangalore

GitHub: [rvitmonisha](https://github.com/rvitmonisha)

---

## License

This project is intended for academic, learning, and research purposes.
