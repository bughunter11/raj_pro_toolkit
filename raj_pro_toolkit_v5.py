#!/usr/bin/env python3
import os, sys, socket, threading, requests
from colorama import Fore, init, Style
import tldextract

init(autoreset=True)
BOLD = "\033[1m"

# === Banner with Version ===
def banner():
    os.system("clear")
    print(Fore.YELLOW + "\n┌" + "─" * 44 + "┐")
    print(Fore.MAGENTA + BOLD + "│      SCRIPT NAME: RAJ_PRO_TOOLKIT         │")
    print(Fore.MAGENTA + BOLD + "│      DEVELOPER   : RAJ_MAKER              │")
    print(Fore.MAGENTA + BOLD + "│      VERSION     : v6.1                   │")
    print(Fore.YELLOW + "└" + "─" * 44 + "┘")

# === Main Menu ===
def menu():
    print(Fore.CYAN + BOLD + "\n┌─────────────── RAJ SCAN MENU ───────────────┐")
    print(Fore.GREEN   + BOLD + " [1] HOST SCANNER")
    print(Fore.CYAN    + BOLD + " [2] SUBFINDER")
    print(Fore.MAGENTA + BOLD + " [3] HOST INFO")
    print(Fore.YELLOW  + BOLD + " [4] SPLIT TXT FILE")
    print(Fore.LIGHTBLUE_EX + BOLD + " [5] SMART SUBFINDER")
    print(Fore.RED     + BOLD + " [0] EXIT")
    print(Fore.CYAN + BOLD + "└─────────────────────────────────────────────┘")

# === Status Filter ===
def is_valid_response(r):
    return r.status_code != 302

# === Option 1: Host Scanner ===
def scan_host(host, port, live_hosts, lock, counter, total):
    try:
        ip = socket.gethostbyname(host)
        url = f"http://{host}:{port}"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        with lock:
            counter[0] += 1
            if is_valid_response(r):
                server = r.headers.get("Server", "Unknown")
                live_hosts.append((host, ip, port, r.status_code, server))
                print(
                    Fore.GREEN + BOLD + f"GET   ",
                    Fore.CYAN + BOLD + f"{r.status_code}   ",
                    Fore.MAGENTA + BOLD + f"{server[:20]:<20} ",
                    Fore.YELLOW + BOLD + f"{port:<5}",
                    Fore.BLUE + BOLD + f"{ip:<15}",
                    Fore.LIGHTWHITE_EX + BOLD + f"{host:<35}"
                )
            show_progress(counter[0], total, len(live_hosts))
    except:
        with lock:
            counter[0] += 1
            show_progress(counter[0], total, len(live_hosts))

def show_progress(scanned, total, live):
    progress = int((scanned / total) * 20)
    bar = "█" * progress + "░" * (20 - progress)
    print(Fore.CYAN + BOLD + f"Scanning [{bar}] {scanned}/{total} live {live}", end='\r')

def host_scanner():
    print(Fore.YELLOW + BOLD + "Enter filename: ", end=''); fn = input().strip()
    print(Fore.YELLOW + BOLD + "Enter port (e.g. 80): ", end=''); port = input().strip()
    print(Fore.YELLOW + BOLD + "Enter threads: ", end=''); threads = int(input().strip())
    try: hosts = [h.strip() for h in open(fn) if h.strip()]
    except: print(Fore.RED + BOLD + "File not found"); return
    total, live_hosts, lock, counter = len(hosts), [], threading.Lock(), [0]
    print(Fore.CYAN + BOLD + "\nMethod Code Server               Port  IP              Host")
    print(Fore.CYAN + BOLD + "------ ----- -------------------- ----- --------------- -----------------------------------")
    def worker():
        while True:
            try: host = hosts.pop()
            except IndexError: break
            scan_host(host, port, live_hosts, lock, counter, total)
    t_list = [threading.Thread(target=worker) for _ in range(threads)]
    [t.start() for t in t_list]
    [t.join() for t in t_list]
    print(Fore.CYAN + BOLD + f"\n\n✔ Total Live: {len(live_hosts)}\n✔ Saved to live_hosts.txt")
    with open("live_hosts.txt", "w") as f:
        for h, ip, p, c, s in live_hosts:
            f.write(f"{h},{ip},{p},{c},{s}\n")
    input(Fore.CYAN + BOLD + "\nPress Enter to return to menu...")

# === Option 2: Subfinder ===

def subfinder():
    print(Fore.CYAN + BOLD + "\n[1] Manual Domain Input")
    print(Fore.CYAN + BOLD + "[2] Load From .txt File")
    method = input(Fore.YELLOW + BOLD + "Choose method [1/2]: ").strip()

    if method == '1':  
        domain = input(Fore.YELLOW + BOLD + "🔤 Enter domain: ").strip()  
        output_file = input(Fore.YELLOW + BOLD + "📁 Enter output file name (e.g., subdomains.txt): ").strip()  

        if not domain:  
            print(Fore.RED + BOLD + "✘ No domain entered.")  
            return  
        if not output_file:  
            print(Fore.RED + BOLD + "✘ No output file specified.")  
            return  

        print(Fore.CYAN + BOLD + f"\n🔍 Scanning: {domain}")  
        try:  
            result = os.popen(f"subfinder -all -d {domain} -silent").read()  
            subdomains = sorted(set(result.strip().split('\n'))) if result.strip() else []  
            count = len(subdomains)  

            with open(output_file, 'w') as f:  
                for sub in subdomains:  
                    f.write(sub + '\n')  

            print(Fore.GREEN + BOLD + f"✅ Found {count} subdomains for {domain}")  
            print(Fore.GREEN + BOLD + f"\n📦 Total Domains Scanned: 1")  
            print(Fore.GREEN + BOLD + f"✅ Total Subdomains Found: {count}")  
            print(Fore.GREEN + BOLD + f"💾 All subdomains saved to: {output_file}")  

        except Exception as e:  
            print(Fore.RED + BOLD + f"❌ Error scanning {domain}: {e}")  

    elif method == '2':  
        output_file = input(Fore.YELLOW + BOLD + "\n📁 Enter name for output file (e.g., subdomains.txt): ").strip()  
        domain_file = input(Fore.YELLOW + BOLD + "📄 Enter path to domain list (.txt): ").strip()  

        if not os.path.isfile(domain_file):  
            print(Fore.RED + BOLD + "✘ File not found!")  
            return  

        with open(domain_file) as f:  
            domains = [line.strip() for line in f if line.strip()]  

        print(Fore.CYAN + BOLD + f"\n📊 Total Domains: {len(domains)}\n")  

        # Clear previous contents before appending new subdomains
        open(output_file, 'w').close()

        total_found = 0  
        total_scanned = 0  

        for domain in domains:  
            print(Fore.CYAN + BOLD + f"🔍 Scanning: {domain}")  
            try:  
                result = os.popen(f"subfinder -all -d {domain} -silent").read()  
                subdomains = sorted(set(result.strip().split('\n'))) if result.strip() else []  
                count = len(subdomains)  
                total_found += count  
                total_scanned += 1  

                with open(output_file, 'a') as f:  
                    for sub in subdomains:  
                        f.write(sub + '\n')  

                print(Fore.GREEN + BOLD + f"✅ Found {count} subdomains for {domain}\n")  

            except Exception as e:  
                print(Fore.RED + BOLD + f"❌ Error scanning {domain}: {e}\n")  

        print(Fore.GREEN + BOLD + f"✅ Total Domains Scanned: {total_scanned}")  
        print(Fore.GREEN + BOLD + f"✅ Total Subdomains Found: {total_found}")  
        print(Fore.GREEN + BOLD + f"💾 All subdomains saved to: {output_file}")  

    else:  
        print(Fore.RED + BOLD + "✘ Invalid option selected.")  

    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to the menu...")

# === Option 3: Host Info ===
def host_info():
    print(Fore.YELLOW + BOLD + "\nEnter single host (e.g. cloudflare.com): ", end="")
    host = input().strip()
    if not host:
        print(Fore.RED + BOLD + "✘ Host is required!")
        return
    print(Fore.YELLOW + BOLD + "Enter port (e.g. 80 or 443): ", end="")
    port = input().strip()
    if not port.isdigit():
        print(Fore.RED + BOLD + "✘ Invalid port number!")
        return
    url = f"http://{host}:{port}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        ip_list = []
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                if ip not in ip_list:
                    ip_list.append(ip)
        except Exception:
            ip_list = ["N/A"]
        r = requests.get(url, headers=headers, timeout=6, allow_redirects=False)
        status = r.status_code
        if status == 302:
            print(Fore.RED + BOLD + f"↪ [302 Redirect] ❌ Not a Zero-Rated Host: {url}")
            return
        print(Fore.GREEN + BOLD + "\n🌐 IP Addresses:")
        for ip in ip_list:
            print(Fore.CYAN + BOLD + f"├─ {ip}")
        cdn = "Cloudflare" if "cloudflare" in r.headers.get("Server", "").lower() or "CF-RAY" in r.headers else "Unknown"
        print(Fore.MAGENTA + BOLD + "\n📦 CDN Detected:")
        print(Fore.CYAN + BOLD + f"└─ {cdn}")
        print(Fore.YELLOW + BOLD + "\n🔍 Request Info:")
        print(Fore.CYAN + BOLD + f"└─ Method: GET")
        print(Fore.CYAN + BOLD + f"└─ Status: {status} OK")
        print(Fore.LIGHTGREEN_EX + BOLD + "\n📬 Response Headers:")
        for key, label in {
            "Date": "├─ Date",
            "Content-Type": "├─ Content-Type",
            "Transfer-Encoding": "├─ Transfer-Encoding",
            "Connection": "├─ Connection",
            "Content-Encoding": "├─ Content-Encoding",
            "X-Frame-Options": "├─ X-Frame-Options",
            "Vary": "├─ Vary",
            "Server": "├─ Server",
            "CF-RAY": "└─ CF-RAY"
        }.items():
            print(Fore.CYAN + BOLD + f"{label}: {r.headers.get(key, 'N/A')}")
    except requests.exceptions.Timeout:
        print(Fore.RED + BOLD + "✘ Connection timed out!")
    except requests.exceptions.ConnectionError:
        print(Fore.RED + BOLD + "✘ Connection error! Host may be unreachable.")
    except Exception as e:
        print(Fore.RED + BOLD + f"✘ Unexpected error: {e}")
    input(Fore.CYAN + BOLD + "\n↩ Press Enter to return to menu...")

# === Option 4: Split TXT File ===
def split_txt_file():
    filename = input(Fore.YELLOW + BOLD + "Enter filename to split: ").strip()
    try:
        with open(filename, "r") as f:
            lines = f.read().splitlines()
    except:
        print(Fore.RED + BOLD + "❌ File not found.")
        return
    total_lines = len(lines)
    if total_lines == 0:
        print(Fore.RED + BOLD + "❌ File is empty.")
        return
    try:
        parts = int(input(Fore.YELLOW + BOLD + "How many parts to split into: ").strip())
        if parts <= 0 or parts > total_lines:
            raise ValueError
    except:
        print(Fore.RED + BOLD + "❌ Invalid number of parts.")
        return
    lines_per_part = total_lines // parts
    remainder = total_lines % parts
    index = 0
    for i in range(parts):
        extra = 1 if i < remainder else 0
        chunk = lines[index : index + lines_per_part + extra]
        with open(f"{filename}_part{i+1}.txt", "w") as f:
            f.write("\n".join(chunk))
        index += lines_per_part + extra
    print(Fore.GREEN + BOLD + f"✔ File split into {parts} parts.")
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

# === Option 5: SMART SUBFINDER ===
def smart_subfinder():
    print(Fore.CYAN + BOLD + "[1] Load From .txt File")
    method = input(Fore.YELLOW + BOLD + "Choose method [1/2]: ").strip()
    if method != '1':
        print(Fore.RED + BOLD + "✘ Only method [1] is supported currently.")
        return

    out_file = input(Fore.YELLOW + BOLD + "📁 Enter name for output file (e.g., subdomains.txt): ").strip()
    file = input(Fore.YELLOW + BOLD + "📄 Enter path to domain list (.txt): ").strip()

    if not os.path.isfile(file):
        print(Fore.RED + BOLD + "✘ File not found!")
        return

    try:
        with open(file) as f:
            raw = [line.strip() for line in f if line.strip()]
        roots = list(set([tldextract.extract(x).registered_domain for x in raw if tldextract.extract(x).registered_domain]))
        print(Fore.CYAN + BOLD + f"\n📊 Total Domains Loaded: {len(roots)}\n")

        total_found = 0
        unique_subs = set()

        # 🔁 Loop through each domain
        for domain in roots:
            print(Fore.YELLOW + BOLD + f"🔍 Scanning: {domain}")
            cmd = f"subfinder -all -d {domain} -silent"
            output = os.popen(cmd).read().splitlines()
            found = len(output)
            total_found += found
            unique_subs.update(output)

            # ✅ Save immediately after each domain scan
            with open(out_file, "a") as out:
                for sub in output:
                    out.write(sub + "\n")

            print(Fore.GREEN + BOLD + f"✅ {found} subdomains found for {domain}\n")

        print(Fore.CYAN + BOLD + f"📦 Total Unique Subdomains Found: {len(unique_subs)}")
        print(Fore.CYAN + BOLD + f"📁 Results saved to: {out_file}")

    except Exception as e:
        print(Fore.RED + BOLD + f"✘ Error: {e}")

    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to the menu...")

# === Exit ===
def exit_script():
    print(Fore.YELLOW + "\n┌" + "─" * 52 + "┐")
    print(Fore.MAGENTA + BOLD + "│       THANKS FOR USING RAJ TOOLKIT!       │")
    print(Fore.CYAN    + BOLD + "│   • Keep Hacking Ethically!               │")
    print(Fore.CYAN    + BOLD + "│   • Knowledge is Power!                   │")
    print(Fore.GREEN   + BOLD + "│   • Made with ♥ by RAJ_MAKER              │")
    print(Fore.YELLOW + "└" + "─" * 52 + "┘")
    sys.exit()

# === Main Runner ===
def main():
    while True:
        banner(); menu()
        choice = input(Fore.YELLOW + BOLD + "\nSelect [0–5]: ").strip()
        if choice == '1': host_scanner()
        elif choice == '2': subfinder()
        elif choice == '3': host_info()
        elif choice == '4': split_txt_file()
        elif choice == '5': smart_subfinder()
        elif choice == '0': exit_script()
        else: print(Fore.RED + BOLD + "Invalid option!")

if __name__ == "__main__":
    main()
