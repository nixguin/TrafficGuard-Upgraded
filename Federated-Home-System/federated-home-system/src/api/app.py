from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
import subprocess
import platform
import jwt
import datetime
import os
import requests
from requests.exceptions import RequestException
import json
from getRouterData import get_router_data_via_ssh
import sqlite3

app = Flask(__name__)
CORS(app)

# Secret key for JWT tokens - in production, use a secure environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key')

# Single dummy guest router
GUEST_ROUTER = {
    'id': 'guest-router',
    'name': 'Guest Router',
    'ip': '192.168.1.100',
    'ports': [80, 443],
    'status': 'active',
    'type': 'guest'
}

# GL.iNet Mango router configuration
ROUTER_CONFIG = {
    'base_url': '192.168.8.1',  # GL.iNet Mango IP
    'username': 'root',  # Default GL.iNet username
    'password': 'Tony2314!@',  # User's router password
    'api_version': 'api'
}

activeRouter = "None"

# GL.iNet Mango Commands
commands = {
    "cpu_usage": "top -bn1 | grep 'CPU:'",
    "memory_usage": "free",
    "wireless_clients": "iw dev wlan0 station dump",
    "firewall_rules": "iptables -L -v",
    "uptime_load": "uptime",
    "network_config": "ifconfig",
    "device_list": "cat /tmp/dhcp.leases",
    "log_output": "logread",
    "bandwidth": "cat /proc/net/dev"
}

def get_local_ip():
    try:
        # Get local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def scan_network():
    # Initialize an empty list to store discovered routers/devices
    routers = []
    seen_ips = set()  # Keep track of IPs we've already processed
    try:
        # Get the local IP address of the computer running this code
        local_ip = get_local_ip()
        print(f"Local IP: {local_ip}")
        
        # If we can't get a local IP, return empty list (we're not on a network)
        if local_ip == "127.0.0.1":
            print("Could not determine local IP, using fallback")
            # Add the guest router as a fallback
            routers.append(GUEST_ROUTER)
            return routers

        # Extract the subnet from the local IP (e.g., 10.0.0.0/24 from 10.0.0.5)
        subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        print(f"Scanning subnet: {subnet}")
        
        # Add common router IPs to check first (including GL.iNet default IPs)
        common_router_ips = [
            f"{'.'.join(local_ip.split('.')[:-1])}.1",  # Common router IP (e.g., 192.168.1.1)
            "192.168.8.1",  # GL.iNet Mango default IP
            "192.168.0.1",  # Another common router IP
            "10.0.0.1",     # Another common router IP
            "10.0.0.138",   # GL.iNet alternative IP
        ]
        
        # Check common router IPs first
        for ip in common_router_ips:
            if ip in seen_ips:  # Skip if we've already processed this IP
                continue
                
            try:
                # Try to get the hostname of the device
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    print(f"Found hostname for {ip}: {hostname}")
                except:
                    # If hostname lookup fails, use a generic name
                    hostname = f"Router at {ip}"
                    print(f"Could not resolve hostname for {ip}")
                
                # Check if this device has common router ports open
                ports = []
                # Check common router and service ports
                for port in [80, 443, 8080, 22, 53, 8081, 8082, 8083]:  # HTTP, HTTPS, alternative HTTP, SSH, DNS, GL.iNet ports
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            ports.append(port)
                            print(f"Port {port} is open on {ip}")
                        sock.close()
                    except Exception as e:
                        print(f"Error checking port {port} for {ip}: {str(e)}")
                
                # Get MAC address for device identification
                mac_address = get_mac_address(ip)
                
                # Check if this device is likely a router
                is_likely_router = (
                    ip.endswith('.1') or
                    'router' in hostname.lower() or
                    'gl' in hostname.lower() or
                    'mango' in hostname.lower() or
                    (mac_address and ('gl' in mac_address.lower() or 'mango' in mac_address.lower())) or
                    len(ports) >= 1
                )
                
                # If device is likely a router, add it to the list
                if is_likely_router:
                    # Determine router type
                    router_type = 'unknown'
                    if 'gl' in hostname.lower() or 'mango' in hostname.lower() or (mac_address and 'gl' in mac_address.lower()):
                        router_type = 'GL.iNet Mango'
                    elif 'guest' in hostname.lower():
                        router_type = 'guest'
                    elif ip.endswith('.1'):
                        router_type = 'Router'
                    
                    # Create unique router ID
                    router_id = f"router-{ip.replace('.', '-')}"
                    
                    # Create router object
                    router = {
                        'id': router_id,
                        'name': hostname,
                        'ip': ip,
                        'ports': ports,
                        'status': 'active',
                        'type': router_type,
                        'mac_address': mac_address
                    }
                    
                    # Only add if we haven't seen this IP before
                    if ip not in seen_ips:
                        routers.append(router)
                        seen_ips.add(ip)
                        print(f"Found router: {router}")
            except Exception as e:
                print(f"Error scanning IP {ip}: {str(e)}")
                continue
        
        # If we found routers, return them
        if routers:
            return routers
        
        # If no routers found, add the guest router as a fallback
        print("No routers found, adding guest router as fallback")
        routers.append(GUEST_ROUTER)
        
    except Exception as e:
        print(f"Error during network scan: {str(e)}")
        # Add the guest router as a fallback
        routers.append(GUEST_ROUTER)
    
    return routers

# Function to get MAC address (if possible)
def get_mac_address(ip):
    try:
        # This is a simplified approach - in reality, getting MAC addresses
        # across subnets requires more complex methods like ARP scanning
        # For demonstration purposes, we'll return a placeholder
        return "00:00:00:00:00:00"
    except:
        return "Unknown"

@app.route('/api/scan-network', methods=['GET'])
def get_available_routers():
    try:
        # Get list of discovered routers/devices
        routers = scan_network()
        print("Found routers:", routers)
        
        # If we have routers, return them
        if routers:
            return jsonify({
                'success': True,
                'routers': routers
            })
        
        # If no routers found, return the guest router as a fallback
        return jsonify({
            'success': True,
            'routers': [GUEST_ROUTER]
        })
        
    except Exception as e:
        # Log the error for debugging
        print(f"Error scanning network: {str(e)}")
        
        # Return the guest router as a fallback
        return jsonify({
            'success': True,
            'routers': [GUEST_ROUTER]
        })

@app.route('/api/getRouterData', methods=['GET', 'POST'])
def get_router_data():
    try:
        if request.method == 'GET':
            return jsonify({
                'success': True,
                'message': 'Router data endpoint is available'
            })
            
        data = request.get_json()
        print("Received router data request:", data)
        
        # Get the router IP from the routerId (e.g., "router-192-168-8-1")
        router_id = data.get('routerId', '')
        print("Router ID:", router_id)
        
        if not router_id:
            print("Error: No router ID provided")
            return jsonify({
                'success': False,
                'error': 'Router ID is required'
            }), 400
            
        # Extract IP from router ID (e.g., "console.gl-inet.com - 192.168.8.1")
        if " - " in router_id:
            router_ip = router_id.split(" - ")[1]
        else:
            # Convert router-192-168-8-1 to 192.168.8.1
            router_ip = router_id.replace('router-', '').replace('-', '.')
        print(f"Attempting to get data from router at {router_ip}")
        
        # First try a simple socket connection to port 80 (web interface)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((router_ip, 80))
            sock.close()
            
            if result != 0:
                error_msg = f"Router {router_ip} is not reachable on port 80"
                print(f"Error: {error_msg}")
                return jsonify({
                    'success': False,
                    'error': f'Cannot connect to router at {router_ip}. Please make sure you are connected to the router network.'
                }), 500
                
            # Try SSH connection with the correct credentials
            test_output = get_router_data_via_ssh(router_ip, ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], "uname -a")
            print("Connection test output:", test_output)
            
            if isinstance(test_output, str) and not test_output.startswith("Error"):
                # Update the router config with the successful IP
                ROUTER_CONFIG['base_url'] = router_ip
                return jsonify({
                    'success': True,
                    'message': 'Successfully retrieved router data',
                    'router': {
                        'ip': router_ip,
                        'status': 'connected',
                        'type': 'GL.iNet Mango',
                        'system_info': test_output
                    }
                })
            else:
                # Try with admin username as fallback
                test_output = get_router_data_via_ssh(router_ip, 'admin', ROUTER_CONFIG['password'], "uname -a")
                if isinstance(test_output, str) and not test_output.startswith("Error"):
                    # Update config if admin works
                    ROUTER_CONFIG['username'] = 'admin'
                    ROUTER_CONFIG['base_url'] = router_ip
                    return jsonify({
                        'success': True,
                        'message': 'Successfully retrieved router data',
                        'router': {
                            'ip': router_ip,
                            'status': 'connected',
                            'type': 'GL.iNet Mango',
                            'system_info': test_output
                        }
                    })
                    
                print(f"SSH connection failed: {test_output}")
                return jsonify({
                    'success': False,
                    'error': f'Failed to authenticate with router. Please check your credentials. Details: {test_output}'
                }), 401
                
        except Exception as e:
            error_msg = str(e)
            print(f"Connection error: {error_msg}")
            return jsonify({
                'success': False,
                'error': f'Failed to connect to router: {error_msg}'
            }), 500
                
    except Exception as e:
        error_msg = str(e)
        print(f"Error getting router data: {error_msg}")
        return jsonify({
            'success': False,
            'error': f'Failed to get router data: {error_msg}'
        }), 500

@app.route('/api/device-details/<ip>', methods=['GET'])
def get_device_details(ip):
    try:
        # Validate that the provided IP address is valid
        try:
            socket.inet_aton(ip)  # This will raise an error if IP is invalid
        except socket.error:
            return jsonify({
                'success': False,
                'error': 'Invalid IP address'
            }), 400
            
        # Try to get the hostname of the device
        try:
            hostname = socket.gethostbyaddr(ip)[0]  # Reverse DNS lookup
        except:
            # If hostname lookup fails, use a generic name with the IP
            hostname = f"Device at {ip}"
            
        # Check which ports are open on the device
        ports = []
        # Common ports to check: HTTP(80), HTTPS(443), alternative HTTP(8080), 
        # SSH(22), DNS(53), DHCP(67,68)
        for port in [80, 443, 8080, 22, 53, 67, 68]:
            # Create a socket to test the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a short timeout to avoid hanging
            sock.settimeout(0.1)
            # Try to connect to the port
            result = sock.connect_ex((ip, port))
            # If connection successful, port is open
            if result == 0:
                ports.append(port)
            # Close the socket
            sock.close()
            
        # Try to determine the device type based on IP and hostname
        device_type = "unknown"
        if ip.endswith('.1'):
            device_type = "router"  # IPs ending in .1 are often routers
        elif "android" in hostname.lower() or "iphone" in hostname.lower():
            device_type = "mobile"  # Check for mobile device indicators in hostname
        elif "laptop" in hostname.lower() or "desktop" in hostname.lower():
            device_type = "computer"  # Check for computer indicators in hostname
            
        # Get network information about the local network
        local_ip = get_local_ip()  # Get the IP of the computer running this code
        subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'  # Calculate the subnet
        
        # Return all the device details in a JSON response
        return jsonify({
            'success': True,
            'device': {
                'ip': ip,  # The IP address of the device
                'hostname': hostname,  # The hostname of the device
                'type': device_type,  # The type of device (router, mobile, etc.)
                'ports': ports,  # List of open ports on the device
                'status': 'active',  # Device is active (we could reach it)
                'network': {
                    'subnet': subnet,  # The subnet the device is on
                    'local_ip': local_ip  # The IP of the computer running this code
                },
                'mac_address': get_mac_address(ip)  # Try to get the MAC address
            }
        })
    except Exception as e:
        # If any error occurs, return an error response
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/data', methods=['GET'])
def get_data():
    print('Request received!')
    try:
        # Fetch router data
        network_log = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["log_output"])
        device_list = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["device_list"])
        general_info = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["network_config"])

        # Format the data to send as a JSON response
        data = {
            "message": "Data fetched from the router!",
            "status": "Success",
            "network_log": network_log,
            "device_list": device_list,
            "general_info": general_info,
        }

        # Recreate and save data to the database
        recreate_database()
        save_data_to_db(data)
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching data: {str(e)}")
        return jsonify({
            "message": "Failed to fetch router data.",
            "status": "Error",
            "error": str(e)
        }), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    print('Fetching logs...')
    try:
        log_output = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["log_output"])
        if isinstance(log_output, str) and "error" not in log_output.lower():
            return jsonify({"status": "Success", "logs": log_output})
        else:
            raise Exception(f"Failed to fetch logs: {log_output}")
    except Exception as e:
        print(f"Error fetching logs: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/devices', methods=['GET'])
def get_devices():
    print('Fetching device list...')
    try:
        device_list = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["device_list"])
        if isinstance(device_list, str) and "error" not in device_list.lower():
            devices = []
            for line in device_list.strip().split("\n"):
                if line:  # Skip empty lines
                    parts = line.split()
                    if len(parts) >= 4:
                        devices.append({
                            "lease_time": parts[0],
                            "mac_address": parts[1],
                            "ip_address": parts[2],
                            "hostname": parts[3] if len(parts) > 3 else "Unknown",
                        })
            return jsonify({"status": "Success", "devices": devices})
        else:
            raise Exception(f"Failed to fetch device list: {device_list}")
    except Exception as e:
        print(f"Error fetching devices: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/cpu_memory', methods=['GET'])
def get_cpu_memory():
    print('Fetching CPU and memory usage...')
    try:
        # Fetch CPU and memory usage data
        cpu_output = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["cpu_usage"])
        memory_output = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["memory_usage"])

        if isinstance(cpu_output, str) and isinstance(memory_output, str) and \
           "error" not in cpu_output.lower() and "error" not in memory_output.lower():
            
            # Parse CPU usage data
            cpu_data = {}
            for part in cpu_output.split():
                if "%" in part:
                    key, value = part.split("%")
                    cpu_data[key] = float(value) if value.replace('.', '').isdigit() else 0

            # Parse Memory usage data
            memory_lines = memory_output.strip().split("\n")
            mem_data = {}
            if len(memory_lines) >= 2:
                headers = memory_lines[0].split()
                values = memory_lines[1].split()
                mem_data = dict(zip(headers, values))

            return jsonify({
                "status": "Success",
                "cpu": cpu_data,
                "memory": mem_data
            })
        else:
            raise Exception(f"Failed to fetch system info: CPU: {cpu_output}, Memory: {memory_output}")
    except Exception as e:
        print(f"Error fetching CPU/memory info: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/wireless_clients', methods=['GET'])
def get_wireless_clients():
    print('Fetching wireless clients...')
    try:
        wireless_clients = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["wireless_clients"])
        if isinstance(wireless_clients, str) and "error" not in wireless_clients.lower():
            # Parse the wireless clients data into a structured format
            clients = []
            current_client = {}
            for line in wireless_clients.strip().split("\n"):
                if line.strip():
                    if "Station" in line:
                        if current_client:
                            clients.append(current_client)
                        current_client = {"mac_address": line.split()[1]}
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        current_client[key.strip()] = value.strip()
            if current_client:
                clients.append(current_client)
                
            return jsonify({"status": "Success", "wireless_clients": clients})
        else:
            raise Exception(f"Failed to fetch wireless clients: {wireless_clients}")
    except Exception as e:
        print(f"Error fetching wireless clients: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/firewall_rules', methods=['GET'])
def get_firewall_rules():
    print('Fetching firewall rules...')
    try:
        firewall_rules = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["firewall_rules"])
        if isinstance(firewall_rules, str) and "error" not in firewall_rules.lower():
            return jsonify({"status": "Success", "firewall_rules": firewall_rules})
        else:
            raise Exception(f"Failed to fetch firewall rules: {firewall_rules}")
    except Exception as e:
        print(f"Error fetching firewall rules: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/uptime_load', methods=['GET'])
def get_uptime_load():
    print('Fetching uptime and load...')
    try:
        uptime_load = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["uptime_load"])
        if isinstance(uptime_load, str) and "error" not in uptime_load.lower():
            return jsonify({"status": "Success", "uptime_load": uptime_load})
        else:
            raise Exception(f"Failed to fetch uptime/load: {uptime_load}")
    except Exception as e:
        print(f"Error fetching uptime/load: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/network_config', methods=['GET'])
def get_network_config():
    print('Fetching network configuration...')
    try:
        network_config = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["network_config"])
        if isinstance(network_config, str) and "error" not in network_config.lower():
            return jsonify({"status": "Success", "network_config": network_config})
        else:
            raise Exception(f"Failed to fetch network config: {network_config}")
    except Exception as e:
        print(f"Error fetching network config: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route('/api/bandwidth', methods=['GET'])
def get_bandwidth():
    print('Fetching bandwidth data...')
    try:
        bandwidth_output = get_router_data_via_ssh(ROUTER_CONFIG['base_url'], ROUTER_CONFIG['username'], ROUTER_CONFIG['password'], commands["bandwidth"])
        if isinstance(bandwidth_output, str) and "error" not in bandwidth_output.lower():
            # Parse and format the output from /proc/net/dev
            lines = bandwidth_output.strip().split("\n")[2:]  # Skip the header lines
            bandwidth_data = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 10:
                    try:
                        bandwidth_data.append({
                            "interface": parts[0].strip(':'),
                            "receive_bytes": int(parts[1]),
                            "transmit_bytes": int(parts[9])
                        })
                    except (ValueError, IndexError) as e:
                        print(f"Error parsing bandwidth data line {line}: {str(e)}")
                        continue
            
            return jsonify({"status": "Success", "bandwidth": bandwidth_data})
        else:
            raise Exception(f"Failed to fetch bandwidth data: {bandwidth_output}")
    except Exception as e:
        print(f"Error fetching bandwidth data: {str(e)}")
        return jsonify({"status": "Error", "error": str(e)}), 500

def recreate_database():
    try:
        conn = sqlite3.connect('router_data.db')
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS router_info")
        cursor.execute("""
            CREATE TABLE router_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT,
                value TEXT
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {str(e)}")
        raise e
    finally:
        if conn:
            conn.close()

def save_data_to_db(data):
    try:
        conn = sqlite3.connect('router_data.db')
        cursor = conn.cursor()
        for key, value in data.items():
            cursor.execute("INSERT INTO router_info (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {str(e)}")
        raise e
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True) 