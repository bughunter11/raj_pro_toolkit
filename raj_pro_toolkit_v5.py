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
    print(Fore.MAGENTA + BOLD + "│      VERSION     : v6.2                   │")
    print(Fore.YELLOW + "└" + "─" * 44 + "┘")

# === Main Menu ===
def menu():
    print(Fore.CYAN + BOLD + "\n┌─────────────── RAJ SCAN MENU ───────────────┐")
    print(Fore.GREEN   + BOLD + " [1] HOST SCANNER")
    print(Fore.CYAN    + BOLD + " [2] SUBFINDER")
    print(Fore.MAGENTA + BOLD + " [3] HOST INFO")
    print(Fore.YELLOW  + BOLD + " [4] SPLIT TXT FILE")
    print(Fore.LIGHTBLUE_EX + BOLD + " [5] SMART SUBFINDER")
    print(Fore.LIGHTGREEN_EX + BOLD + " [6] UPDATE TOOL")
    print(Fore.RED     + BOLD + " [7] UNINSTALL TOOL")  # New uninstall option
    print(Fore.RED     + BOLD + " [0] EXIT")
    print(Fore.CYAN + BOLD + "└─────────────────────────────────────────────┘")

# === Status Filter ===
def is_valid_response(r):
    return r.status_code != 302

# === Option 1: Host Scanner ===
import os, socket, threading, time, requests
from colorama import Fore, init, Style

init(autoreset=True)
BOLD = "\033[1m"
session = requests.Session()
session.keep_alive = False
socket.setdefaulttimeout(5)

# === Valid Response Filter ===
def is_valid_response(r):
    return r.status_code != 302

# === Scan Host on All Ports and Scheme ===
def scan_host(host, ports, live_hosts, lock, counter, total, check_https, output_file):
    try:
        ip = socket.gethostbyname(host)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close"
        }

        for port in ports:
            schemes = ["https", "http"] if port in ["443", "8443"] and check_https else ["http"]
            for scheme in schemes:
                url = f"{scheme}://{host}:{port}"
                for _ in range(2):  # Retry logic
                    try:
                        r = session.get(url, headers=headers, timeout=(5, 12), allow_redirects=False)
                        break
                    except:
                        time.sleep(0.2)
                        continue
                else:
                    with lock:
                        counter[0] += 1
                        show_progress(counter[0], total, len(live_hosts))
                    continue

                with lock:
                    counter[0] += 1
                    if is_valid_response(r):
                        server = r.headers.get("Server", "Unknown")
                        live_hosts.append((host, ip, port, r.status_code, server))
                        print(
                            Fore.GREEN + BOLD + "GET   ",
                            Fore.CYAN + BOLD + f"{r.status_code:<5}",
                            Fore.MAGENTA + BOLD + f"{server[:20]:<20}",
                            Fore.YELLOW + BOLD + f"{port:<5}",
                            Fore.BLUE + BOLD + f"{ip:<15}",
                            Fore.LIGHTWHITE_EX + BOLD + f"{host:<35}"
                        )
                        with open(output_file, "a") as f:
                            f.write(f"{host},{ip},{port},{r.status_code},{server}\n")
                    show_progress(counter[0], total, len(live_hosts))

    except (socket.gaierror, socket.timeout):
        with lock:
            counter[0] += len(ports) * (2 if check_https else 1)
            show_progress(counter[0], total, len(live_hosts))

# === Show Progress ===
def show_progress(scanned, total, live):
    progress = int((scanned / total) * 20)
    bar = "█" * progress + "░" * (20 - progress)
    print(Fore.CYAN + BOLD + f"Scanning [{bar}] {scanned}/{total} live {live}", end='\r')

# === HOST SCANNER Main ===
def host_scanner():
    print(Fore.GREEN + BOLD + "[1] PRO SCAN")
    print(Fore.CYAN + BOLD + "[2] SYSTEM SCAN")
    choice = input(Fore.YELLOW + BOLD + "\nChoose an option [1/2]: ").strip()

    if choice == '1':
        pro_scan()
    elif choice == '2':
        system_scan()
    else:
        print(Fore.RED + BOLD + "❌ Invalid choice.")
        return

# === PRO SCAN ===
def pro_scan():
    print(Fore.YELLOW + BOLD + "\n📄 Enter filename: ", end=''); fn = input().strip()
    print(Fore.YELLOW + BOLD + "🔌 Enter port(s) (e.g. 80,443,8080): ", end=''); ports_input = input().strip()
    print(Fore.YELLOW + BOLD + "🔐 Scan HTTPS too? (y/n): ", end=''); check_https = input().strip().lower() == 'y'
    print(Fore.YELLOW + BOLD + "⚙️  Enter threads: ", end=''); threads = int(input().strip())
    print(Fore.YELLOW + BOLD + "💾 Output file name (e.g. live_hosts.txt): ", end=''); output_file = input().strip()

    try:
        hosts = [h.strip() for h in open(fn) if h.strip()]
        ports = [p.strip() for p in ports_input.split(',') if p.strip().isdigit()]
    except:
        print(Fore.RED + BOLD + "❌ Invalid file or ports."); return

    total = len(hosts) * len(ports) * (2 if check_https else 1)
    live_hosts, lock, counter = [], threading.Lock(), [0]

    print(Fore.CYAN + BOLD + "\nMethod Code Server               Port  IP              Host")
    print(Fore.CYAN + BOLD + "------ ----- -------------------- ----- --------------- -----------------------------------")

    def worker():
        while True:
            try: host = hosts.pop()
            except IndexError: break
            scan_host(host, ports, live_hosts, lock, counter, total, check_https, output_file)

    t_list = [threading.Thread(target=worker) for _ in range(threads)]
    for t in t_list: t.start()
    for t in t_list: t.join()

    print(Fore.CYAN + BOLD + f"\n\n✔ Total Live: {len(live_hosts)}\n✔ Saved to {output_file}")
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

# === SYSTEM SCAN ===
def system_scan():
    print(Fore.YELLOW + BOLD + "\n📄 Enter filename: ", end=''); fn = input().strip()
    print(Fore.YELLOW + BOLD + "🔌 Enter port(s) (e.g. 80,443): ", end=''); ports_input = input().strip()
    try:
        hosts = [h.strip() for h in open(fn) if h.strip()]
        ports = [p.strip() for p in ports_input.split(',') if p.strip().isdigit()]
    except:
        print(Fore.RED + BOLD + "❌ File or ports error."); return

    output_file = "system_live.txt"
    total = len(hosts) * len(ports)
    live_hosts, lock, counter = [], threading.Lock(), [0]

    print(Fore.CYAN + BOLD + "\nMethod Code Server               Port  IP              Host")
    print(Fore.CYAN + BOLD + "------ ----- -------------------- ----- --------------- -----------------------------------")

    def scan_basic(host):
        for port in ports:
            try:
                ip = socket.gethostbyname(host)
                url = f"http://{host}:{port}"
                r = requests.get(url, timeout=(5, 10), allow_redirects=False)
                if r.status_code != 302:
                    server = r.headers.get("Server", "Unknown")
                    with lock:
                        live_hosts.append((host, ip, port, r.status_code, server))
                        print(
                            Fore.GREEN + BOLD + "GET   ",
                            Fore.CYAN + BOLD + f"{r.status_code:<5}",
                            Fore.MAGENTA + BOLD + f"{server[:20]:<20}",
                            Fore.YELLOW + BOLD + f"{port:<5}",
                            Fore.BLUE + BOLD + f"{ip:<15}",
                            Fore.LIGHTWHITE_EX + BOLD + f"{host:<35}"
                        )
                        with open(output_file, "a") as f:
                            f.write(f"{host},{ip},{port},{r.status_code},{server}\n")
            except:
                pass
            finally:
                with lock:
                    counter[0] += 1
                    show_progress(counter[0], total, len(live_hosts))

    def worker():
        while True:
            try: host = hosts.pop()
            except IndexError: break
            scan_basic(host)

    t_list = []
    for _ in range(min(32, os.cpu_count() * 4)):
        t_list.append(threading.Thread(target=worker))
    for t in t_list: t.start()
    for t in t_list: t.join()

    print(Fore.CYAN + BOLD + f"\n\n✔ Total Live: {len(live_hosts)}\n✔ Saved to {output_file}")
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

# === HIGH POWER SCAN ===
def high_power_scan():
    print(Fore.YELLOW + BOLD + "\n📄 Enter host file: ", end=''); fn = input().strip()
    print(Fore.YELLOW + BOLD + "🔌 Enter ports (e.g. 80,443): ", end=''); ports = input().strip()
    print(Fore.YELLOW + BOLD + "⚙️  Enter threads (e.g. 100): ", end=''); threads = input().strip()
    print(Fore.YELLOW + BOLD + "💾 Output file (e.g. high_power_live.txt): ", end=''); output_file = input().strip()

    if not os.path.isfile(fn):
        print(Fore.RED + BOLD + "❌ Host file not found."); return

    if not os.path.isfile("high_scan"):
        print(Fore.RED + BOLD + "❌ C++ binary 'high_scan' missing.")
        print(Fore.YELLOW + BOLD + "💡 Compile using: clang++ high_scan.cpp -o high_scan")
        return

    print(Fore.GREEN + BOLD + "\n🚀 Launching HIGH POWER SCAN...\n")
    os.system(f"./high_scan {fn} {ports} {output_file} {threads}")
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")
    host_scanner()

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

# === Option 6: Update Tool ===
def update_tool():
    print(Fore.YELLOW + BOLD + "\nChecking for updates...")
    
    # GitHub raw URL where your script is hosted
    GITHUB_RAW_URL = "https://raw.githubusercontent.com/bughunter11/raj_pro_toolkit/refs/heads/main/raj_pro_toolkit_v5.py"
    
    try:
        # Get current version from the banner
        current_version = "v6.1"  # You should extract this from your banner
        
        # Fetch the latest version from GitHub
        response = requests.get(GITHUB_RAW_URL, timeout=10)
        if response.status_code == 200:
            # Extract version from the remote file
            remote_content = response.text
            version_line = next(line for line in remote_content.split('\n') if "VERSION" in line)
            latest_version = version_line.split(":")[1].strip().replace('"', '').strip()
            
            if latest_version > current_version:
                print(Fore.GREEN + BOLD + f"Update available: {current_version} → {latest_version}")
                choice = input(Fore.YELLOW + BOLD + "Do you want to update? [y/N]: ").strip().lower()
                if choice == 'y':
                    # Backup current version
                    backup_name = f"raj_pro_toolkit_backup_v{current_version}.py"
                    with open(backup_name, 'w') as backup_file:
                        with open(__file__, 'r') as current_file:
                            backup_file.write(current_file.read())
                    
                    # Write new version
                    with open(__file__, 'w') as f:
                        f.write(remote_content)
                    
                    print(Fore.GREEN + BOLD + "✔ Update successful!")
                    print(Fore.CYAN + BOLD + f"✔ Backup saved as {backup_name}")
                    print(Fore.YELLOW + BOLD + "Please restart the tool to apply changes.")
                else:
                    print(Fore.YELLOW + BOLD + "Update canceled.")
            else:
                print(Fore.GREEN + BOLD + "✔ You already have the latest version!")
        else:
            print(Fore.RED + BOLD + "✘ Could not check for updates (connection failed)")
    except Exception as e:
        print(Fore.RED + BOLD + f"✘ Update check failed: {str(e)}")
    
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

# === Option 7: Uninstall Tool ===
def uninstall_tool():
    print(Fore.RED + BOLD + "\n⚠️ WARNING: This will remove RAJ_PRO_TOOLKIT and its dependencies!")
    confirm = input(Fore.YELLOW + BOLD + "Are you sure? (y/N): ").strip().lower()

    if confirm != 'y':
        print(Fore.YELLOW + BOLD + "❌ Uninstall canceled.")
        input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")
        return

    print(Fore.RED + BOLD + "\n🧹 Removing RAJ_PRO_TOOLKIT...")

    try:
        # Get full path to this script
        script_path = os.path.abspath(sys.argv[0])

        # Remove main script file
        if os.path.exists(script_path):
            os.remove(script_path)
            print(Fore.GREEN + BOLD + f"✓ Removed: {script_path}")

        # Remove installed binaries (safely check)
        os.system("rm -f $PREFIX/bin/subfinder")
        os.system("rm -f $PREFIX/bin/rajpro")

        # Uninstall Python packages (check for pip)
        if os.system("command -v pip > /dev/null") == 0:
            os.system("pip uninstall -y requests colorama tldextract beautifulsoup4")

        print(Fore.GREEN + BOLD + "✓ Uninstall complete!")
        print(Fore.YELLOW + BOLD + "💡 You may also want to run: pkg uninstall golang")
        print(Fore.CYAN + BOLD + "👋 Goodbye!")

        sys.exit()

    except Exception as e:
        print(Fore.RED + BOLD + f"✘ Error during uninstall: {e}")
        input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

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
        choice = input(Fore.YELLOW + BOLD + "\nSelect [0–7]: ").strip()
        if choice == '1': host_scanner()
        elif choice == '2': subfinder()
        elif choice == '3': host_info()
        elif choice == '4': split_txt_file()
        elif choice == '5': smart_subfinder()
        elif choice == '6': update_tool()
        elif choice == '7': uninstall_tool()  # New uninstall handler
        elif choice == '0': exit_script()
        else: print(Fore.RED + BOLD + "Invalid option!")

if __name__ == "__main__":
    main()