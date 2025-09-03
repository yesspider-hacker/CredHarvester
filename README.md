# 🔑 CredHarvester++

CredHarvester++ is a **Red Team credential & token discovery tool for Windows**.  
It hunts for secrets across:
- Process memory (PoC: reads small chunk from each process)
- Environment variables

⚠️ **Disclaimer**: This tool is for educational and authorized red team testing **only**.  
Do not use it on systems you don’t have explicit permission to test.

---

## ✨ Features
- Regex-based detection of:
  - `password=...`
  - AWS keys (`AKIA...`)
  - GitHub tokens (`ghp_...`)
  - JWTs (`eyJ...`)
- Colorful, structured CLI output
- Lightweight PoC (expandable to full memory scanner)

---

## 📦 Installation

```powershell
git clone https://github.com/<your-username>/CredHarvester.git
cd CredHarvester
pip install -r requirements.txt
