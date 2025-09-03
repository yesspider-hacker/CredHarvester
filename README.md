# 🔑 CredHarvester++

CredHarvester++ is a **Red Team credential & token discovery tool for Windows**.  
It hunts for secrets across:
- 🧠 **Process memory** (PoC: scans a portion of process memory)  
- 🌍 **Environment variables**  

⚠️ **Disclaimer**: This tool is for **educational and authorized red team testing only**.  
Do **NOT** use it on systems you don’t own or have explicit permission to test.

---

## ✨ Features
- Regex-based detection of:
  - `password=...`
  - AWS keys (`AKIA...`)
  - GitHub tokens (`ghp_...`)
  - JWTs (`eyJ...`)
- Scan all processes or a **specific PID**
- Colorful & structured CLI output
- Lightweight PoC (expandable to full memory scanner)

---

## 📦 Installation

Clone the repo and install requirements:

```powershell
git clone https://github.com/<your-username>/CredHarvester.git
cd CredHarvester
pip install -r requirements.txt
```

###Scan Process Memory
```powershell
python credharvester.py --process
```
###Scan a Specific Process by PID
```powershell
python credharvester.py --process --pid 4321
```
###Scan All (Process Memory + Env Vars)
```powershell
python credharvester.py --all
```

