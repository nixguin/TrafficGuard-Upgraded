import paramiko

# Router Configuration
ROUTER_IP = "192.168.50.1"
USERNAME = "NotFound"
PASSWORD = "NotFound"  # Replace with actual password
PORT = 22  # Change if needed

# Commands to Retrieve Important Data
commands = {
    "cpu_usage": "cat /proc/stat | head -n 1",  # CPU usage statistics
    "memory_usage": "cat /proc/meminfo | head -n 5",  # Memory usage details
    "wireless_clients_2.4GHz": "wl -i eth1 assoclist",  # Connected wireless clients (2.4GHz)
    "wireless_clients_5GHz": "wl -i eth2 assoclist",  # Connected wireless clients (5GHz)
    "firewall_rules": "iptables -L -v",  # Lists firewall rules
    "uptime_load": "uptime",  # System uptime and load average
    "network_config": "ip addr show",  # Network interfaces and IP addresses
    "device_list": "cat /tmp/clientlist.json",  # List of DHCP clients (connected devices)
    "log_output": "logread",  # System logs
    "bandwidth": "cat /proc/net/dev"  # Network interface traffic statistics
}

def ssh_run_commands(ip, user, pwd, commands, port=22):
    """Connects to the router via SSH and executes important diagnostic commands."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {ip} as {user}...")
        ssh.connect(ip, username=user, password=pwd, port=port)

        for desc, cmd in commands.items():
            print(f"\n[Executing] {desc}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            errors = stderr.read().decode().strip()

            if output:
                print(f"[Output]:\n{output}")
            if errors:
                print(f"[Errors]:\n{errors}")

    except paramiko.AuthenticationException:
        print("❌ Authentication failed. Check username/password.")
    except paramiko.SSHException as e:
        print(f"❌ SSH connection error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    finally:
        ssh.close()
        print("\nConnection closed.")

# Run the script
if __name__ == "__main__":
    ssh_run_commands(ROUTER_IP, USERNAME, PASSWORD, commands, PORT)
