import subprocess
import platform

def block_ip(ip, callback=None):
    system = platform.system()

    if system == "Windows":
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block {ip}", "dir=in", "action=block", f"remoteip={ip}"]
    elif system == "Linux":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    elif system == "Darwin":
        print("macOS blocking not implemented.")
        return
    else:
        print(f"Unsupported OS: {system}")
        return

    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Blocked IP: {ip}")
        if callback:
            callback(ip)  # call callback after blocking
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block IP {ip}: {e}")