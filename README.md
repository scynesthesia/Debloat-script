# ⚔️ Scynesthesia Windows Optimizer (Nahue Windows Optimizer)

> A modular, hardware-aware Windows optimization suite designed for performance, privacy, and stability.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)

**Scynesthesia Windows Optimizer** is a PowerShell-based utility that debloats Windows, enhances privacy by disabling telemetry, and optimizes system performance. Unlike generic "cleaners," it features **hardware detection** (SSD vs HDD, Laptop vs Desktop) to apply safe, context-aware tweaks.

## 🚀 Features

### 🛡️ 1. Main / SOC Profile (Safe)
* **Privacy Hardening:** Disables deep telemetry, activity feed, and tracking services.
* **Safe Debloat:** Removes pre-installed "bloatware" apps without breaking the Microsoft Store or Xbox essential services.
* **Smart Cleaning:** Clears temporary files and Windows Update cache.
* **Hardware Awareness:** Automatically adjusts *SysMain* (Superfetch) based on whether you use an SSD or HDD.

### ⚡ 2. Aggressive Profile (Low-End PC)
* Includes all Safe features plus:
* **Deep Debloat:** Removes secondary apps (People, Mixed Reality, etc.).
* **Background App Restriction:** Prevents apps from running in the background.
* **Hibernation Logic:** Intelligently disables hibernation on Desktops to save space, but keeps it on Laptops.

### 🎮 3. Gaming Mode (FPS Boost Add-on)
A standalone module for gamers that can be applied on top of any profile:
* **Network Optimization:** Disables network throttling and Nagle's algorithm for lower ping/jitter.
* **Scheduler Tweak:** Forces Windows to prioritize Games (High Priority) over background processes for CPU/GPU.
* **Custom Power Injection:** Modifies the current power plan to disable Core Parking, prevent USB suspension, and force NVMe drives to remain active.

### 🔧 4. Repair Tools
Built-in troubleshooting for common issues:
* **Network Reset:** Clears DNS cache, releases IP, and resets Winsock (optional).
* **System Integrity:** Runs `sfc /scannow` to find and repair corrupt Windows system files.

---

## 🛠️ Configuration

Scynesthesia Optimizer avoids hardcoded lists. You can customize exactly what gets removed by editing the configuration file:

* **File:** `config/apps.json`
* **SafeRemove:** Apps removed in the Main/Safe profile.
* **AggressiveRemove:** Apps removed in the Aggressive profile.
* **AggressiveTweaksRemove:** Extra apps removed only in the Aggressive preset.

*Example: To keep the Xbox App, simply remove `"Microsoft.XboxApp"` from the list in `apps.json` before running the script.*

---

## 📦 Installation & Usage

1.  **Download** the repository (or clone it):
    ```powershell
    git clone [https://github.com/scynesthesia/debloat-script.git](https://github.com/scynesthesia/debloat-script.git)
    ```
2.  **Run the script** as Administrator:
    * Right-click `scynesthesiaoptimizer.ps1` and select **"Run with PowerShell"**.
    * *Or via terminal:*
        ```powershell
        Set-ExecutionPolicy Unrestricted -Scope Process
        .\scynesthesiaoptimizer.ps1
        ```

3.  **Follow the Menu:**
    * Select `1` for a safe, general optimization.
    * Select `3` if you are preparing the PC for gaming.
    * Select `4` if you need to fix network or system issues.

---

## ⚙️ Modular Architecture

The project is structured for easy maintenance and safety:

* `scynesthesiaoptimizer.ps1`: The orchestrator (Main Menu).
* `modules/`:
    * `ui.psm1`: Interface and user interaction logic.
    * `privacy.psm1`: Telemetry and privacy registry tweaks.
    * `debloat.psm1`: App removal and disk cleanup functions.
    * `performance.psm1`: Hardware detection and basic power plans.
    * `aggressive.psm1`: Deep optimization for older hardware.
    * `gaming.psm1`: Latency reduction and CPU priority management.
    * `repair.psm1`: Network and OS integrity tools.

---

## ⚠️ Disclaimer

**Use at your own risk.**
While this script includes safety checks (Restore Points, Laptop detection), modifying Windows registry and services always carries a small risk. Always ensure you have a backup of your important data before running optimization tools.

---

**Author:** [scynesthesia](https://github.com/scynesthesia)
**License:** MIT
