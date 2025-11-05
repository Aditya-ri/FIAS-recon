# FIAS-recon
A Robust Network scanner tool 

# FIAS - The FIAS Recon Scanner
*Exploring the Scanner LANDSCAPE*



FIAS is a fast, multi-threaded, and modular network port scanner built in Python. It's designed for quick recon, service identification, and... well, finding fiascos.

---

## ⚡ Features
* **Warp-Speed Scanning:** Uses multi-threading (`-w`) to scan ports concurrently.
* **Service "Brain":** Uses a modular `probes.json` file to identify services—no hard-coded logic.
* **Branded UI:** A truly unique, randomized ASCII art banner on every run.
* **Cross-Platform:** Built with Python and `colorama` to run on (almost) anything.

---

## 🚀 Installation
FIAS is designed to be installed as a system-wide command on Linux.

**1. Clone the repository:**
```bash
git clone https://github.com/Aditya-ri/FIAS-recon.git
```

2. Navigate into the directory:

```Bash
cd FIAS-recon
```

3. Run the installer: This will create a system-wide symbolic link named FIAS.

```Bash
sudo ./install.sh
```

4. Done! Open a new terminal (or type hash -r) and you're ready to go.

Usage
Just type FIAS from any directory.

Basic Syntax

```Bash
FIAS -t <TARGET> -p <PORTS> [OPTIONS]
```
Examples
Scan a single host for common ports:

```Bash
FIAS -t 127.0.0.1 -p 22,80,443
```
Scan a full subnet for a port range, using 200 threads:

```Bash
FIAS -t 192.168.1.0/24 -p 1-1000 -w 200
```

All Options
```Bash
Flag	Long Flag	Description
-t	--target	(Required) The target IP, hostname, or CIDR block.
-p	--ports	(Required) The ports to scan (e.G., 80, 22-100, 80,443).
-w	--workers	The number of concurrent threads (default: 100).
-h	--help	Show this help message.
```
Author
Aditya Chhimpa

GitHub: https://github.com/Aditya-ri
