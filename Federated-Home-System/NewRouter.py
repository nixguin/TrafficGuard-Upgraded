import paramiko

#Configuration
ROUTER_IP = "192.168.50.1"
USERNAME = "NotFound"
PASSWORD = "NotFound"  # Replace with actual password
PORT = 22  # Change if you use a custom SSH port

COMMANDS = [
    "cat /proc/net/arp",       # Shows connected devices
    "netstat -an",             # Active connections
    "uptime",                  # Optional: system uptime
]

def ssh_run_commands(ip, user, pwd, commands, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=user, password=pwd, port=port)
        for cmd in commands:
            print(f"\nRunning: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode()
            errors = stderr.read().decode()
            if output:
                print(output)
            if errors:
                print("Errors:", errors)
    except Exception as e:
        print("Connection failed:", e)
    finally:
        ssh.close()