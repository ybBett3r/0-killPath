# NEXUS Task Sentinel

### Game-Optimized Process Authority Engine (PowerShell 7)

---

## 🚀 Overview

NEXUS Task Sentinel is a **high-performance, real-time process management engine** designed to **maximize system efficiency under load**, particularly for gaming and compute-intensive workflows.

It extends beyond traditional task managers by leveraging:

* Native Windows APIs (P/Invoke)
* Privilege escalation (`SeDebugPrivilege`)
* JSON-driven optimization profiles

---

## ⚡ Features

### 🔐 Elevated Process Control

* Enables `SeDebugPrivilege`
* Manipulates protected processes
* Full authority over:

  * priority
  * affinity
  * memory
  * termination

---

### 🎮 Profile-Based Optimization

Apply predefined system tuning profiles:

| Mode        | Purpose                     |
| ----------- | --------------------------- |
| MaxFPS      | Prioritize game performance |
| Streaming   | Balance game + encoder      |
| Workstation | Stability and multitasking  |

Profiles are defined via:

```
regex → priority/action
```

---

### 🧠 Native Execution Layer

Direct Win32 integration:

* `AdjustTokenPrivileges`
* `OpenProcess`
* `SetPriorityClass`
* `SetProcessAffinityMask`
* `TerminateProcess`

No reliance on external tools.

---

### 📊 Real-Time Telemetry

Structured logging system:

```
TRACE | INFO | OK | WARN | ERR | CRIT | STEP | GAME
```

* Color-coded console output
* Persistent log files
* Timestamped execution tracking

---

### ⚙️ Headless Automation

Run without UI:

```powershell
.\NexusTaskSentinel.ps1 -Mode MaxFPS -Headless
```

Ideal for:

* startup optimization
* scheduled tasks
* automation pipelines

---

### 🧹 Explorer Control

Optional shell termination:

* Kills `explorer.exe` for performance gains
* Tracks state for safe restoration

---

### 🔎 Intelligent Filtering

* Regex-based process filtering
* CPU usage thresholds
* Output limiting for performance

---

### ♻️ State Recovery

Tracks:

* original process priorities
* system state changes

Ensures safe rollback after execution.

---

## 📦 Installation

### Requirements

* PowerShell 7+
* Administrator privileges

### Setup

```powershell
git clone <repo>
cd NexusTaskSentinel
```

---

## ▶️ Usage

### Apply Profile

```powershell
.\NexusTaskSentinel.ps1 -Mode MaxFPS
```

### Headless Execution

```powershell
.\NexusTaskSentinel.ps1 -Mode Streaming -Headless
```

### Filter Processes

```powershell
.\NexusTaskSentinel.ps1 -FilterPattern '^(chrome|discord)' -MinCPU 5
```

---

## ⚙️ Parameters

| Parameter         | Description                  |
| ----------------- | ---------------------------- |
| `-Mode`           | Profile name                 |
| `-Headless`       | Run without UI               |
| `-FilterPattern`  | Regex filter                 |
| `-MinCPU`         | Minimum CPU threshold        |
| `-RefreshMs`      | UI refresh rate              |
| `-Limit`          | Max displayed processes      |
| `-NoExplorerKill` | Prevent explorer termination |
| `-InstallRoot`    | Custom config/log path       |

---

## 🧪 Use Cases

* 🎮 Competitive gaming optimization
* 🎥 Streaming performance balancing
* 🧠 Resource isolation experiments
* ⚡ Automated system tuning
* 🔬 Process behavior analysis

---

## ⚠️ Safety Notes

* Requires administrator privileges
* Can terminate critical processes
* Misuse may destabilize system

Use with precision.

---

## 🧩 Design Philosophy

NEXUS Task Sentinel is built on:

* **Maximum control**
* **Zero abstraction overhead**
* **Deterministic execution**
* **Automation-first workflows**

---

## 📜 License

MIT (or specify)

---

## 🔧 Future Enhancements

* Dynamic adaptive profiles
* ML-driven process prioritization
* Remote orchestration support
* Cross-node execution

---

## 🧠 Summary

This tool transforms Windows into a **policy-driven execution environment**, enabling **surgical control over system resources** with minimal overhead.

---
