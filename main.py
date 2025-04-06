import streamlit as st
import pandas as pd
import numpy as np
import time
import hashlib
import socket
import ipaddress
import subprocess
import platform
import threading
import queue
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import networkx as nx
from ping3 import ping
import psutil
import pickle
import os
import nmap
import scapy.all as scapy
from scapy.layers import http
import netifaces
import json
import requests
import plotly.express as px
import plotly.graph_objects as go
import plotly.figure_factory as ff
from plotly.subplots import make_subplots
from typing import Dict, List, Tuple, Optional
import logging
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# File to store user credentials
USER_DB_FILE = "user_credentials.pkl"

# File to store scan results
SCAN_RESULTS_FILE = "scan_results.pkl"

# File to store device profiles
DEVICE_PROFILES_FILE = "device_profiles.json"

# Common ports to scan
COMMON_PORTS = {
    'web': [80, 443, 8080],
    'file': [21, 22, 23],
    'print': [9100, 515, 631],
    'remote': [3389, 5900],
    'network': [161, 162, 389, 636]
}

# Device type signatures
DEVICE_SIGNATURES = {
    'router': {
        'ports': [80, 443, 8080, 22],
        'services': ['http', 'https', 'ssh'],
        'os_fingerprints': ['Cisco', 'Juniper', 'MikroTik']
    },
    'printer': {
        'ports': [9100, 515, 631],
        'services': ['printer', 'ipp', 'lpd'],
        'os_fingerprints': ['HP', 'Epson', 'Canon', 'Brother']
    },
    'computer': {
        'ports': [445, 139, 3389],
        'services': ['smb', 'rdp'],
        'os_fingerprints': ['Windows', 'Linux', 'MacOS']
    }
}

def get_network_interfaces():
    """Get information about all network interfaces."""
    interfaces = {}
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            interfaces[interface] = {
                'ipv4': addrs[netifaces.AF_INET],
                'mac': addrs.get(netifaces.AF_LINK, [{'addr': 'Unknown'}])[0]['addr'],
                'status': 'up' if netifaces.AF_INET in addrs else 'down'
            }
    return interfaces

def get_mac_address(ip: str) -> Optional[str]:
    """Get MAC address for a given IP address."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None
    except Exception as e:
        logger.error(f"Error getting MAC address for {ip}: {e}")
        return None

def scan_ports(ip: str, ports: List[int] = None) -> Dict[int, str]:
    """Scan ports on a given IP address."""
    if ports is None:
        ports = [port for port_list in COMMON_PORTS.values() for port in port_list]
    
    open_ports = {}
    
    try:
        # Check if nmap is available
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            nmap_available = True
        except (subprocess.SubprocessError, FileNotFoundError):
            nmap_available = False
            st.warning("Nmap is not installed. Some features will be limited. Please install Nmap for full functionality.")
        
        if nmap_available:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments=f'-sS -sV -p{",".join(map(str, ports))} -T4')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        if state == 'open':
                            open_ports[port] = service
    except Exception as e:
        logger.warning(f"Nmap scanning failed: {e}. Falling back to basic socket scanning.")
        st.warning("Using basic socket scanning (limited functionality)")
    
    # Always perform basic socket scanning as fallback
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports[port] = service
            sock.close()
        except:
            continue
    
    return open_ports

def detect_device_type(ip: str, open_ports: Dict[int, str], os_info: str) -> str:
    """Detect device type based on open ports and OS information."""
    device_scores = {}
    
    for device_type, signature in DEVICE_SIGNATURES.items():
        score = 0
        # Check ports
        for port in open_ports:
            if port in signature['ports']:
                score += 1
        # Check services
        for service in open_ports.values():
            if service in signature['services']:
                score += 1
        # Check OS fingerprints
        for fingerprint in signature['os_fingerprints']:
            if fingerprint.lower() in os_info.lower():
                score += 2
        
        device_scores[device_type] = score
    
    # Return device type with highest score
    return max(device_scores.items(), key=lambda x: x[1])[0] if device_scores else "Unknown"

def os_fingerprint(ip: str) -> str:
    """Perform OS fingerprinting on a given IP address."""
    try:
        # Check if nmap is available
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            nmap_available = True
        except (subprocess.SubprocessError, FileNotFoundError):
            nmap_available = False
            st.warning("Nmap is not installed. OS fingerprinting will be limited.")
        
        if nmap_available:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O --version-intensity 5')
            if ip in nm.all_hosts():
                os_info = nm[ip].get('osmatch', [])
                if os_info:
                    return os_info[0].get('name', 'Unknown')
    except Exception as e:
        logger.warning(f"Nmap OS fingerprinting failed: {e}. Using basic OS detection.")
        st.warning("Using basic OS detection (limited accuracy)")
    
    # Fallback to basic OS detection
    try:
        # Try to get OS info from TTL
        response = ping(ip, timeout=1)
        if response is not None:
            # Basic OS detection based on TTL
            if response > 0.1:  # Higher latency might indicate Windows
                return "Windows"
            else:
                return "Linux/Unix"
    except:
        pass
    return 'Unknown'

def capture_packets(interface: str, count: int = 100) -> List[Dict]:
    """Capture network packets on a given interface."""
    packets = []
    try:
        sniff(prn=lambda x: packets.append({
            'src': x[scapy.IP].src,
            'dst': x[scapy.IP].dst,
            'proto': x[scapy.IP].proto,
            'len': len(x),
            'time': datetime.now().isoformat()
        }), count=count, iface=interface, store=0)
    except Exception as e:
        logger.error(f"Error capturing packets: {e}")
    return packets

def analyze_traffic(packets: List[Dict]) -> Dict:
    """Analyze network traffic from captured packets."""
    analysis = {
        'total_packets': len(packets),
        'protocols': {},
        'top_talkers': {},
        'total_bytes': 0
    }
    
    for packet in packets:
        # Count protocols
        proto = packet['proto']
        analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1
        
        # Count top talkers
        for ip in [packet['src'], packet['dst']]:
            analysis['top_talkers'][ip] = analysis['top_talkers'].get(ip, 0) + packet['len']
        
        # Total bytes
        analysis['total_bytes'] += packet['len']
    
    return analysis

def monitor_qos(ip: str, duration: int = 60) -> Dict:
    """Monitor Quality of Service metrics for a given IP."""
    start_time = time.time()
    results = {
        'latency': [],
        'jitter': [],
        'packet_loss': [],
        'bandwidth': []
    }
    
    while time.time() - start_time < duration:
        # Measure latency
        response_time = ping(ip, timeout=1)
        if response_time is not None:
            results['latency'].append(response_time * 1000)  # Convert to ms
        
        # Measure bandwidth
        bandwidth = measure_bandwidth(ip)
        if bandwidth:
            results['bandwidth'].append(bandwidth)
        
        time.sleep(1)
    
    # Calculate statistics
    if results['latency']:
        results['avg_latency'] = sum(results['latency']) / len(results['latency'])
        results['jitter'] = calculate_jitter(results['latency'])
    
    if results['bandwidth']:
        results['avg_bandwidth'] = sum(results['bandwidth']) / len(results['bandwidth'])
    
    return results

def calculate_jitter(latencies: List[float]) -> float:
    """Calculate jitter from a list of latencies."""
    if len(latencies) < 2:
        return 0
    jitter = 0
    for i in range(1, len(latencies)):
        jitter += abs(latencies[i] - latencies[i-1])
    return jitter / (len(latencies) - 1)

def measure_bandwidth(ip: str) -> Optional[float]:
    """Measure bandwidth to a given IP."""
    try:
        # Create a TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, 80))
        
        # Send data and measure time
        start_time = time.time()
        sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
        sock.recv(1024)
        end_time = time.time()
        
        # Calculate bandwidth
        duration = end_time - start_time
        if duration > 0:
            return 1024 / duration  # bytes per second
    except Exception as e:
        logger.error(f"Error measuring bandwidth for {ip}: {e}")
    finally:
        sock.close()
    return None

# Check if user database exists, if not create it
if not os.path.exists(USER_DB_FILE):
    default_users = {
        "admin": hashlib.sha256("admin123".encode()).hexdigest(),
        "user": hashlib.sha256("user123".encode()).hexdigest()
    }
    with open(USER_DB_FILE, "wb") as f:
        pickle.dump(default_users, f)

# Load user credentials
def load_users():
    try:
        with open(USER_DB_FILE, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return {}

# Save scan results
def save_scan_results(results):
    with open(SCAN_RESULTS_FILE, "wb") as f:
        pickle.dump(results, f)

# Load scan results
def load_scan_results():
    try:
        with open(SCAN_RESULTS_FILE, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return {}

# Authentication functions
def verify_password(username, password):
    users = load_users()
    if username in users:
        return users[username] == hashlib.sha256(password.encode()).hexdigest()
    return False

def add_user(username, password):
    users = load_users()
    users[username] = hashlib.sha256(password.encode()).hexdigest()
    with open(USER_DB_FILE, "wb") as f:
        pickle.dump(users, f)

# Network discovery functions
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_subnet(ip):
    # Assuming it's a /24 subnet
    ip_parts = ip.split('.')
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

def scan_ip(ip, timeout=1):
    try:
        response_time = ping(ip, timeout=timeout)
        if response_time is not None:
            try:
                hostname = socket.getfqdn(ip)
            except:
                hostname = "Unknown"
            return ip, True, hostname, response_time
        return ip, False, "N/A", None
    except Exception as e:
        return ip, False, "N/A", None

def get_available_networks():
    """Get all available networks on the system."""
    networks = []
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                netmask = addr['netmask']
                # Calculate network address
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                networks.append({
                    'interface': interface,
                    'ip': ip,
                    'netmask': netmask,
                    'network': str(network),
                    'broadcast': str(network.broadcast_address)
                })
    return networks

def scan_network(subnet, progress_bar=None):
    """Scan a network for active devices."""
    # Generate fake devices based on the subnet
    network_prefix = subnet.split('/')[0]
    fake_devices = []
    
    # Generate different types of devices based on network
    if network_prefix.startswith('192.168.1'):
        fake_devices = [
            {
                'ip': '192.168.1.1',
                'hostname': 'Router-01',
                'response_time': 0.002,
                'mac': '00:11:22:33:44:55',
                'open_ports': {80: 'http', 443: 'https', 22: 'ssh'},
                'os': 'Cisco IOS',
                'device_type': 'router'
            },
            {
                'ip': '192.168.1.101',
                'hostname': 'Laptop-01',
                'response_time': 0.005,
                'mac': 'AA:BB:CC:DD:EE:FF',
                'open_ports': {445: 'smb', 3389: 'rdp', 139: 'netbios'},
                'os': 'Windows 10',
                'device_type': 'computer'
            },
            {
                'ip': '192.168.1.102',
                'hostname': 'Printer-01',
                'response_time': 0.008,
                'mac': '11:22:33:44:55:66',
                'open_ports': {9100: 'printer', 515: 'lpd', 631: 'ipp'},
                'os': 'HP Printer OS',
                'device_type': 'printer'
            }
        ]
    elif network_prefix.startswith('10.0.0'):
        fake_devices = [
            {
                'ip': '10.0.0.1',
                'hostname': 'Server-Router',
                'response_time': 0.003,
                'mac': 'FF:EE:DD:CC:BB:AA',
                'open_ports': {80: 'http', 443: 'https', 22: 'ssh'},
                'os': 'Ubuntu Server',
                'device_type': 'router'
            },
            {
                'ip': '10.0.0.101',
                'hostname': 'Database-Server',
                'response_time': 0.004,
                'mac': 'AA:BB:CC:DD:EE:FF',
                'open_ports': {3306: 'mysql', 5432: 'postgresql', 22: 'ssh'},
                'os': 'CentOS',
                'device_type': 'computer'
            },
            {
                'ip': '10.0.0.102',
                'hostname': 'Web-Server',
                'response_time': 0.005,
                'mac': '11:22:33:44:55:66',
                'open_ports': {80: 'http', 443: 'https', 8080: 'http-proxy'},
                'os': 'Ubuntu Server',
                'device_type': 'computer'
            }
        ]
    elif network_prefix.startswith('172.16.0'):
        fake_devices = [
            {
                'ip': '172.16.0.1',
                'hostname': 'VM-Host',
                'response_time': 0.003,
                'mac': '22:33:44:55:66:77',
                'open_ports': {22: 'ssh', 80: 'http', 443: 'https'},
                'os': 'ESXi',
                'device_type': 'computer'
            },
            {
                'ip': '172.16.0.201',
                'hostname': 'VM-01',
                'response_time': 0.004,
                'mac': '33:44:55:66:77:88',
                'open_ports': {22: 'ssh', 80: 'http', 443: 'https'},
                'os': 'CentOS',
                'device_type': 'computer'
            },
            {
                'ip': '172.16.0.202',
                'hostname': 'VM-02',
                'response_time': 0.005,
                'mac': '44:55:66:77:88:99',
                'open_ports': {22: 'ssh', 80: 'http', 443: 'https'},
                'os': 'Ubuntu Server',
                'device_type': 'computer'
            }
        ]
    else:
        # Default fake devices for unknown networks
        fake_devices = [
            {
                'ip': f"{network_prefix}.1",
                'hostname': 'Default-Router',
                'response_time': 0.002,
                'mac': '00:11:22:33:44:55',
                'open_ports': {80: 'http', 443: 'https', 22: 'ssh'},
                'os': 'Generic Router OS',
                'device_type': 'router'
            },
            {
                'ip': f"{network_prefix}.101",
                'hostname': 'Default-Device-01',
                'response_time': 0.005,
                'mac': 'AA:BB:CC:DD:EE:FF',
                'open_ports': {445: 'smb', 3389: 'rdp'},
                'os': 'Windows 10',
                'device_type': 'computer'
            }
        ]
    
    # Simulate scanning progress
    if progress_bar:
        for i in range(100):
            time.sleep(0.01)
            progress_bar.progress(i + 1)
    
    return fake_devices   

# Performance monitoring functions
def measure_latency(ip, count=4):
    results = []
    for _ in range(count):
        response_time = ping(ip, timeout=1)
        if response_time is not None:
            results.append(response_time * 1000)  # Convert to ms
        time.sleep(0.2)
    
    if results:
        return {
            'min': min(results),
            'max': max(results),
            'avg': sum(results) / len(results),
            'packet_loss': (count - len(results)) / count * 100
        }
    else:
        return {
            'min': None,
            'max': None,
            'avg': None,
            'packet_loss': 100
        }

def get_bandwidth_usage():
    # Get current network stats
    net_io = psutil.net_io_counters()
    stats = {
        'bytes_sent': net_io.bytes_sent,
        'bytes_recv': net_io.bytes_recv,
        'packets_sent': net_io.packets_sent,
        'packets_recv': net_io.packets_recv,
        'errin': net_io.errin,
        'errout': net_io.errout,
        'dropin': net_io.dropin,
        'dropout': net_io.dropout,
        'timestamp': datetime.now()
    }
    return stats

def calculate_bandwidth_rate(prev_stats, current_stats):
    if not prev_stats:
        return {
            'upload_speed': 0,
            'download_speed': 0,
            'duration': 0
        }
    
    time_diff = (current_stats['timestamp'] - prev_stats['timestamp']).total_seconds()
    
    if time_diff <= 0:
        return {
            'upload_speed': 0,
            'download_speed': 0,
            'duration': 0
        }
    
    upload_diff = current_stats['bytes_sent'] - prev_stats['bytes_sent']
    download_diff = current_stats['bytes_recv'] - prev_stats['bytes_recv']
    
    upload_speed = upload_diff / time_diff
    download_speed = download_diff / time_diff
    
    return {
        'upload_speed': upload_speed,
        'download_speed': download_speed,
        'duration': time_diff
    }

def generate_fake_monitoring_data():
    """Generate fake monitoring data for demonstration."""
    # Generate random variations for more realistic data
    base_latency = np.random.uniform(2.0, 8.0)
    latency_variation = np.random.uniform(0.5, 2.0)
    
    return {
        'latency': {
            'min': round(base_latency - latency_variation, 1),
            'max': round(base_latency + latency_variation, 1),
            'avg': round(base_latency, 1),
            'packet_loss': round(np.random.uniform(0.1, 1.5), 1)
        },
        'qos': {
            'latency': [round(np.random.uniform(2.5, 7.5), 1) for _ in range(10)],
            'jitter': round(np.random.uniform(0.3, 1.2), 1),
            'bandwidth': round(np.random.uniform(1500, 3500), 1)  # KB/s
        },
        'traffic': {
            'total_packets': int(np.random.uniform(800, 2000)),
            'total_bytes': int(np.random.uniform(1500000, 3500000)),  # 1.5-3.5 MB
            'protocols': {
                'TCP': int(np.random.uniform(600, 1000)),
                'UDP': int(np.random.uniform(200, 400)),
                'ICMP': int(np.random.uniform(50, 150)),
                'HTTP': int(np.random.uniform(300, 600)),
                'HTTPS': int(np.random.uniform(200, 400)),
                'DNS': int(np.random.uniform(100, 200))
            },
            'top_talkers': {
                '192.168.1.101': int(np.random.uniform(800000, 1500000)),
                '192.168.1.102': int(np.random.uniform(500000, 1000000)),
                '10.0.0.101': int(np.random.uniform(300000, 700000)),
                '172.16.0.201': int(np.random.uniform(200000, 500000)),
                '192.168.1.1': int(np.random.uniform(100000, 300000))
            }
        },
        'bandwidth': {
            'download_speed': round(np.random.uniform(1500, 3500), 1),  # KB/s
            'upload_speed': round(np.random.uniform(800, 2000), 1),    # KB/s
            'history': [
                {
                    'timestamp': datetime.now().replace(second=i),
                    'download_speed': round(1500 + np.random.uniform(-200, 200), 1),
                    'upload_speed': round(1000 + np.random.uniform(-100, 100), 1)
                }
                for i in range(10)
            ]
        }
    }

def generate_fake_network_data():
    """Generate fake network data for testing."""
    fake_networks = [
        {
            'interface': 'Wi-Fi',
            'ip': '192.168.1.100',
            'netmask': '255.255.255.0',
            'network': '192.168.1.0/24',
            'broadcast': '192.168.1.255',
            'status': 'up',
            'speed': '866.7 Mbps',
            'signal_strength': '85%'
        },
        {
            'interface': 'Ethernet',
            'ip': '10.0.0.50',
            'netmask': '255.255.255.0',
            'network': '10.0.0.0/24',
            'broadcast': '10.0.0.255',
            'status': 'up',
            'speed': '1 Gbps',
            'signal_strength': '100%'
        },
        {
            'interface': 'Virtual Network',
            'ip': '172.16.0.100',
            'netmask': '255.255.0.0',
            'network': '172.16.0.0/16',
            'broadcast': '172.16.255.255',
            'status': 'up',
            'speed': '10 Gbps',
            'signal_strength': '100%'
        },
        {
            'interface': 'Mobile Hotspot',
            'ip': '192.168.43.100',
            'netmask': '255.255.255.0',
            'network': '192.168.43.0/24',
            'broadcast': '192.168.43.255',
            'status': 'up',
            'speed': '150 Mbps',
            'signal_strength': '75%'
        }
    ]
    
    fake_devices = [
        # Network Infrastructure
        {
            'ip': '192.168.1.1',
            'hostname': 'Router-01',
            'response_time': round(np.random.uniform(0.001, 0.003), 3),
            'mac': '00:11:22:33:44:55',
            'open_ports': {80: 'http', 443: 'https', 22: 'ssh', 53: 'dns', 67: 'dhcp'},
            'os': 'Cisco IOS 15.2',
            'device_type': 'router',
            'vendor': 'Cisco',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.2',
            'hostname': 'Switch-01',
            'response_time': round(np.random.uniform(0.001, 0.002), 3),
            'mac': '00:11:22:33:44:66',
            'open_ports': {22: 'ssh', 161: 'snmp', 162: 'snmptrap'},
            'os': 'Cisco IOS 15.0',
            'device_type': 'switch',
            'vendor': 'Cisco',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.3',
            'hostname': 'AP-01',
            'response_time': round(np.random.uniform(0.002, 0.004), 3),
            'mac': '00:11:22:33:44:77',
            'open_ports': {80: 'http', 443: 'https', 22: 'ssh', 161: 'snmp'},
            'os': 'Cisco AireOS 8.5',
            'device_type': 'access_point',
            'vendor': 'Cisco',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        
        # Computers and Workstations
        {
            'ip': '192.168.1.101',
            'hostname': 'Laptop-01',
            'response_time': round(np.random.uniform(0.003, 0.006), 3),
            'mac': 'AA:BB:CC:DD:EE:FF',
            'open_ports': {445: 'smb', 3389: 'rdp', 139: 'netbios', 80: 'http', 443: 'https'},
            'os': 'Windows 10 Pro',
            'device_type': 'computer',
            'vendor': 'Dell',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.102',
            'hostname': 'Desktop-01',
            'response_time': round(np.random.uniform(0.002, 0.004), 3),
            'mac': 'AA:BB:CC:DD:EE:00',
            'open_ports': {445: 'smb', 3389: 'rdp', 139: 'netbios', 80: 'http', 443: 'https'},
            'os': 'Windows 11 Pro',
            'device_type': 'computer',
            'vendor': 'HP',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.103',
            'hostname': 'MacBook-01',
            'response_time': round(np.random.uniform(0.002, 0.004), 3),
            'mac': 'AA:BB:CC:DD:EE:11',
            'open_ports': {445: 'smb', 5900: 'vnc', 80: 'http', 443: 'https'},
            'os': 'macOS 13.0',
            'device_type': 'computer',
            'vendor': 'Apple',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        
        # Printers and Scanners
        {
            'ip': '192.168.1.201',
            'hostname': 'Printer-01',
            'response_time': round(np.random.uniform(0.005, 0.008), 3),
            'mac': '11:22:33:44:55:66',
            'open_ports': {9100: 'printer', 515: 'lpd', 631: 'ipp', 80: 'http', 443: 'https'},
            'os': 'HP Printer OS 2.0',
            'device_type': 'printer',
            'vendor': 'HP',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.202',
            'hostname': 'Scanner-01',
            'response_time': round(np.random.uniform(0.005, 0.008), 3),
            'mac': '11:22:33:44:55:77',
            'open_ports': {9100: 'printer', 515: 'lpd', 631: 'ipp', 80: 'http', 443: 'https'},
            'os': 'Epson Scanner OS 1.5',
            'device_type': 'printer',
            'vendor': 'Epson',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        
        # Mobile Devices
        {
            'ip': '192.168.1.301',
            'hostname': 'iPhone-01',
            'response_time': round(np.random.uniform(0.003, 0.006), 3),
            'mac': '22:33:44:55:66:77',
            'open_ports': {80: 'http', 443: 'https', 554: 'rtsp'},
            'os': 'iOS 16.0',
            'device_type': 'mobile',
            'vendor': 'Apple',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.302',
            'hostname': 'Android-01',
            'response_time': round(np.random.uniform(0.003, 0.006), 3),
            'mac': '22:33:44:55:66:88',
            'open_ports': {80: 'http', 443: 'https', 554: 'rtsp'},
            'os': 'Android 13',
            'device_type': 'mobile',
            'vendor': 'Samsung',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        
        # IoT Devices
        {
            'ip': '192.168.1.401',
            'hostname': 'Smart-TV-01',
            'response_time': round(np.random.uniform(0.004, 0.007), 3),
            'mac': '33:44:55:66:77:88',
            'open_ports': {80: 'http', 443: 'https', 554: 'rtsp', 1900: 'ssdp'},
            'os': 'Samsung Tizen OS',
            'device_type': 'iot',
            'vendor': 'Samsung',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.402',
            'hostname': 'Security-Cam-01',
            'response_time': round(np.random.uniform(0.005, 0.008), 3),
            'mac': '44:55:66:77:88:99',
            'open_ports': {80: 'http', 443: 'https', 554: 'rtsp', 37777: 'dahua'},
            'os': 'Dahua Firmware',
            'device_type': 'iot',
            'vendor': 'Dahua',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.403',
            'hostname': 'Thermostat-01',
            'response_time': round(np.random.uniform(0.005, 0.008), 3),
            'mac': '55:66:77:88:99:00',
            'open_ports': {80: 'http', 443: 'https', 5683: 'coap'},
            'os': 'Nest OS 2.0',
            'device_type': 'iot',
            'vendor': 'Google',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '192.168.1.404',
            'hostname': 'Smart-Bulb-01',
            'response_time': round(np.random.uniform(0.005, 0.008), 3),
            'mac': '66:77:88:99:00:11',
            'open_ports': {80: 'http', 443: 'https', 5683: 'coap'},
            'os': 'Philips Hue OS',
            'device_type': 'iot',
            'vendor': 'Philips',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        
        # Servers
        {
            'ip': '10.0.0.101',
            'hostname': 'Web-Server-01',
            'response_time': round(np.random.uniform(0.002, 0.004), 3),
            'mac': 'FF:EE:DD:CC:BB:AA',
            'open_ports': {80: 'http', 443: 'https', 22: 'ssh', 3306: 'mysql', 5432: 'postgresql'},
            'os': 'Ubuntu Server 20.04 LTS',
            'device_type': 'server',
            'vendor': 'Dell',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '10.0.0.102',
            'hostname': 'File-Server-01',
            'response_time': round(np.random.uniform(0.002, 0.004), 3),
            'mac': 'FF:EE:DD:CC:BB:BB',
            'open_ports': {445: 'smb', 139: 'netbios', 22: 'ssh', 2049: 'nfs'},
            'os': 'Windows Server 2019',
            'device_type': 'server',
            'vendor': 'Dell',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        
        # Virtual Machines
        {
            'ip': '172.16.0.201',
            'hostname': 'VM-Web-01',
            'response_time': round(np.random.uniform(0.003, 0.005), 3),
            'mac': '22:33:44:55:66:77',
            'open_ports': {22: 'ssh', 80: 'http', 443: 'https', 3306: 'mysql', 8080: 'http-proxy'},
            'os': 'CentOS 8',
            'device_type': 'virtual_machine',
            'vendor': 'VMware',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'ip': '172.16.0.202',
            'hostname': 'VM-DB-01',
            'response_time': round(np.random.uniform(0.003, 0.005), 3),
            'mac': '33:44:55:66:77:88',
            'open_ports': {22: 'ssh', 3306: 'mysql', 5432: 'postgresql', 27017: 'mongodb'},
            'os': 'Ubuntu Server 20.04 LTS',
            'device_type': 'virtual_machine',
            'vendor': 'VMware',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    ]
    
    return fake_networks, fake_devices

def generate_university_network_data():
    """Generate fake university network data for testing."""
    # University building codes
    buildings = {
        'ADM': 'Administration Building',
        'LIB': 'Library',
        'SCI': 'Science Building',
        'ENG': 'Engineering Building',
        'ART': 'Arts Building',
        'SPT': 'Sports Complex',
        'DOR': 'Dormitories',
        'STU': 'Student Center',
        'MED': 'Medical Building',
        'BUS': 'Business School'
    }
    
    # Create admin switches (core layer)
    admin_switches = [
        {
            'id': 'CORE-SW-01',
            'name': 'Core Switch 01',
            'ip': '10.10.0.1',
            'location': 'Main Data Center',
            'model': 'Cisco Catalyst 9600',
            'status': 'active',
            'uptime': '45 days, 12:34:56',
            'cpu_load': f"{random.randint(10, 25)}%",
            'memory_usage': f"{random.randint(25, 45)}%",
            'firmware': 'IOS-XE 17.3.4',
            'ports': 48,
            'active_ports': random.randint(30, 40),
            'mac': '00:1A:2B:3C:4D:5E',
            'last_reboot': (datetime.now() - timedelta(days=random.randint(30, 60))).strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'id': 'CORE-SW-02',
            'name': 'Core Switch 02',
            'ip': '10.10.0.2',
            'location': 'Main Data Center',
            'model': 'Cisco Catalyst 9600',
            'status': 'active',
            'uptime': '30 days, 08:45:23',
            'cpu_load': f"{random.randint(10, 25)}%",
            'memory_usage': f"{random.randint(25, 45)}%",
            'firmware': 'IOS-XE 17.3.4',
            'ports': 48,
            'active_ports': random.randint(30, 40),
            'mac': '00:1A:2B:3C:4D:5F',
            'last_reboot': (datetime.now() - timedelta(days=random.randint(20, 40))).strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'id': 'DIST-SW-DC',
            'name': 'Distribution Switch - Data Center',
            'ip': '10.10.1.1',
            'location': 'Data Center',
            'model': 'Cisco Catalyst 9500',
            'status': 'active',
            'uptime': '60 days, 14:22:05',
            'cpu_load': f"{random.randint(15, 30)}%",
            'memory_usage': f"{random.randint(30, 50)}%",
            'firmware': 'IOS-XE 17.2.1',
            'ports': 24,
            'active_ports': random.randint(15, 20),
            'mac': '00:2B:3C:4D:5E:6F',
            'last_reboot': (datetime.now() - timedelta(days=random.randint(50, 70))).strftime('%Y-%m-%d %H:%M:%S')
        }
    ]
    
    # Create distribution switches (building distribution layer)
    distribution_switches = []
    
    # Simulate a power outage in a specific area (affecting multiple buildings)
    power_outage_area = random.choice([True, False])
    affected_buildings = random.sample(list(buildings.keys()), random.randint(1, 3)) if power_outage_area else []
    
    # Simulate a scheduled maintenance on one building
    maintenance_building = random.choice(list(buildings.keys())) if random.random() < 0.2 else None
    
    for i, (code, building) in enumerate(buildings.items(), 1):
        # Determine switch status based on various factors
        switch_status = 'active'
        
        # If building is in power outage area
        if code in affected_buildings:
            switch_status = 'inactive'
            reason = 'Power outage'
        # If building is under maintenance
        elif code == maintenance_building:
            switch_status = 'inactive'
            reason = 'Scheduled maintenance'
        # Random hardware failure (rare)
        elif random.random() < 0.05:  # 5% chance of random failure
            switch_status = 'inactive'
            reason = random.choice(['Hardware failure', 'Software crash', 'Link failure'])
        else:
            reason = 'Operational'
        
        uptime = f'{random.randint(1, 90)} days, {random.randint(0, 24):02d}:{random.randint(0, 60):02d}:{random.randint(0, 60):02d}' if switch_status == 'active' else '0 days, 00:00:00'
        
        distribution_switches.append({
            'id': f'{code}-SW-01',
            'name': f'{building} Main Switch',
            'ip': f'10.20.{i}.1',
            'location': f'{building}, 1st Floor, Network Room',
            'model': 'Cisco Catalyst 9300',
            'status': switch_status,
            'uptime': uptime,
            'cpu_load': f'{random.randint(5, 40)}%' if switch_status == 'active' else '0%',
            'memory_usage': f'{random.randint(20, 60)}%' if switch_status == 'active' else '0%',
            'firmware': 'IOS-XE 17.1.2',
            'ports': 24,
            'active_ports': random.randint(12, 24) if switch_status == 'active' else 0,
            'mac': f'00:{i:02X}:3C:4D:5E:6F',
            'connected_to': 'CORE-SW-01' if i % 2 == 0 else 'CORE-SW-02',
            'last_reboot': (datetime.now() - timedelta(days=random.randint(1, 90))).strftime('%Y-%m-%d %H:%M:%S') if switch_status == 'active' else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reason': reason
        })
    
    # Create access points
    access_points = []
    ap_counter = 1
    
    # Current time to simulate time-based issues
    current_hour = datetime.now().hour
    
    # Simulate high usage times (affecting AP performance)
    high_usage_time = 8 <= current_hour <= 17  # Business hours
    
    # Buildings with high student population (more APs, more clients)
    high_density_buildings = ['LIB', 'STU', 'DOR'] 
    
    # Buildings with older infrastructure (more failures)
    older_infrastructure = ['ADM', 'ART']
    
    # Simulate recent firmware update (causing some issues)
    recent_firmware_update = random.choice([True, False])
    firmware_affected_aps = []
    if recent_firmware_update:
        # Random selection of APs affected by firmware update
        firmware_issue_chance = 0.15  # 15% of APs might have issues after update
    else:
        firmware_issue_chance = 0
    
    for i, (code, building) in enumerate(buildings.items(), 1):
        # Determine number of APs based on building type
        if code in high_density_buildings:
            num_aps = random.randint(6, 10)  # More APs in high-density areas
        else:
            num_aps = random.randint(3, 6)
        
        # Get the status of the distribution switch this AP connects to
        connected_switch = f'{code}-SW-01'
        switch_status = next((s['status'] for s in distribution_switches if s['id'] == connected_switch), 'inactive')
        
        for j in range(1, num_aps + 1):
            floor = random.randint(1, 5)
            wing = random.choice(["North", "South", "East", "West"])
            ap_status = 'active'
            status_reason = 'Operational'
            
            # If the distribution switch is down, all APs connected to it are down
            if switch_status == 'inactive':
                ap_status = 'inactive'
                status_reason = f'Switch {connected_switch} is down'
            else:
                # Apply other factors for AP status
                
                # 1. Random hardware failure chance
                base_failure_chance = 0.03  # 3% baseline chance of failure
                
                # 2. Older infrastructure has higher failure rates
                if code in older_infrastructure:
                    base_failure_chance += 0.05  # Additional 5% chance
                
                # 3. Firmware issues
                firmware_issue = random.random() < firmware_issue_chance
                if firmware_issue:
                    firmware_affected_aps.append(f'{code}-AP-{j:02d}')
                    ap_status = 'inactive'
                    status_reason = 'Firmware compatibility issue'
                    
                # 4. Random failure based on combined factors
                elif random.random() < base_failure_chance:
                    ap_status = 'inactive'
                    status_reason = random.choice(['Hardware failure', 'Configuration error', 'Connection timeout'])
                    
                # 5. Congestion during high usage times in dense areas
                elif high_usage_time and code in high_density_buildings and random.random() < 0.1:
                    # AP still works but has performance issues
                    status_reason = 'High utilization'
            
            # Calculate client load based on time of day and building type
            max_clients = 50 if code in high_density_buildings else 30
            time_multiplier = 0.8 if high_usage_time else 0.3
            
            if ap_status == 'active':
                uptime = f'{random.randint(1, 60)} days, {random.randint(0, 24):02d}:{random.randint(0, 60):02d}:{random.randint(0, 60):02d}'
                connected_clients = int(max_clients * time_multiplier * random.uniform(0.7, 1.0))
                signal_quality = random.randint(70, 95) if code not in older_infrastructure else random.randint(60, 85)
                cpu_load = random.randint(5, 30) if code in high_density_buildings and high_usage_time else random.randint(5, 15)
                memory_usage = random.randint(20, 50) if code in high_density_buildings and high_usage_time else random.randint(15, 35)
            else:
                uptime = '0 days, 00:00:00'
                connected_clients = 0
                signal_quality = 0
                cpu_load = 0
                memory_usage = 0
            
            # Set firmware version and last update date
            if recent_firmware_update and f'{code}-AP-{j:02d}' in firmware_affected_aps:
                firmware_version = 'AireOS 8.10.151.0 (New)'
                last_updated = (datetime.now() - timedelta(days=random.randint(1, 3))).strftime('%Y-%m-%d')
            else:
                firmware_version = 'AireOS 8.10.145.0'
                last_updated = (datetime.now() - timedelta(days=random.randint(30, 120))).strftime('%Y-%m-%d')
            
            access_points.append({
                'id': f'AP-{ap_counter:03d}',
                'name': f'{code}-AP-{j:02d}',
                'ip': f'10.20.{i}.{100+j}',
                'location': f'{building}, Floor {floor}, {wing} Wing',
                'model': 'Cisco Aironet 2800',
                'status': ap_status,
                'status_reason': status_reason,
                'uptime': uptime,
                'cpu_load': f'{cpu_load}%',
                'memory_usage': f'{memory_usage}%',
                'firmware': firmware_version,
                'last_updated': last_updated,
                'connected_clients': connected_clients,
                'max_clients': max_clients,
                'channel': [1, 6, 11][j % 3] if ap_status == 'active' else 'N/A',
                'signal_strength': f'{signal_quality}%' if ap_status == 'active' else 'N/A',
                'mac': f'00:AP:{ap_counter:02X}:4D:5E:6F',
                'connected_to': connected_switch,
                'floor': floor,
                'wing': wing,
                'building_code': code,
                'building_name': building
            })
            ap_counter += 1
    
    # Add client type distribution for each active AP
    client_types = ['Laptop', 'Smartphone', 'Tablet', 'IoT Device', 'Other']
    
    for ap in access_points:
        if ap['connected_clients'] > 0:
            ap['client_distribution'] = {}
            clients_left = ap['connected_clients']
            
            # Assign clients to different device types based on building
            if ap['building_code'] in ['LIB', 'SCI', 'ENG', 'BUS']:
                # Academic buildings - more laptops
                laptop_percent = random.uniform(0.6, 0.8)
                smartphone_percent = random.uniform(0.1, 0.3)
                tablet_percent = random.uniform(0.05, 0.15)
                iot_percent = random.uniform(0.01, 0.05)
            elif ap['building_code'] in ['DOR', 'STU']:
                # Student areas - more smartphones and IoT
                laptop_percent = random.uniform(0.3, 0.5)
                smartphone_percent = random.uniform(0.3, 0.5)
                tablet_percent = random.uniform(0.05, 0.15)
                iot_percent = random.uniform(0.05, 0.1)
            else:
                # Administrative and other buildings
                laptop_percent = random.uniform(0.4, 0.6)
                smartphone_percent = random.uniform(0.2, 0.4)
                tablet_percent = random.uniform(0.1, 0.2)
                iot_percent = random.uniform(0.02, 0.05)
            
            # Calculate clients per type
            laptop_clients = int(ap['connected_clients'] * laptop_percent)
            smartphone_clients = int(ap['connected_clients'] * smartphone_percent)
            tablet_clients = int(ap['connected_clients'] * tablet_percent)
            iot_clients = int(ap['connected_clients'] * iot_percent)
            other_clients = ap['connected_clients'] - (laptop_clients + smartphone_clients + tablet_clients + iot_clients)
            
            ap['client_distribution'] = {
                'Laptop': laptop_clients,
                'Smartphone': smartphone_clients,
                'Tablet': tablet_clients,
                'IoT Device': iot_clients,
                'Other': other_clients
            }
            
            # Add traffic data
            ap['data_transferred'] = round(random.uniform(0.5, 5.0) * ap['connected_clients'], 2)  # GB
            
            # Bandwidth usage (Mbps)
            ap['bandwidth_usage'] = round(random.uniform(1, 20) * (ap['connected_clients'] / ap['max_clients']), 2)
    
    return admin_switches, distribution_switches, access_points

# Main app
def main():
    st.set_page_config(
        page_title="Network Analysis Tool",
        page_icon="🌐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # State initialization
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'active_devices' not in st.session_state:
        st.session_state.active_devices = []
    if 'prev_bandwidth_stats' not in st.session_state:
        st.session_state.prev_bandwidth_stats = None
    if 'bandwidth_history' not in st.session_state:
        st.session_state.bandwidth_history = []
    if 'latency_history' not in st.session_state:
        st.session_state.latency_history = {}
    
    # Login page
    if not st.session_state.authenticated:
        st.title("Network Analysis Tool - Login")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.button("Login"):
                if verify_password(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid username or password")
        
        with col2:
            st.subheader("Register")
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            if st.button("Register"):
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                elif not new_username or not new_password:
                    st.error("Username and password cannot be empty")
                else:
                    add_user(new_username, new_password)
                    st.success("User registered successfully")
    
    # Main app after login
    else:
        st.sidebar.title(f"Welcome, {st.session_state.username}")
        
        menu = st.sidebar.radio(
            "Navigation",
            ["Network Discovery", "Performance Monitoring", "University Network Monitoring"]
        )
        
        if st.sidebar.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.rerun()
        
        if menu == "Network Discovery":
            st.title("Network Discovery and Mapping")
            
            # Get fake network data
            fake_networks, _ = generate_fake_network_data()
            
            # Display available networks
            st.subheader("Available Networks")
            network_options = [f"{net['network']} ({net['interface']})" for net in fake_networks]
            selected_network = st.selectbox("Select Network to Scan", network_options)
            
            if selected_network:
                # Extract network address from selection
                network_address = selected_network.split(' ')[0]
                
                # Display network details
                for net in fake_networks:
                    if net['network'] == network_address:
                        with st.expander("Network Details"):
                            st.write(f"Interface: {net['interface']}")
                            st.write(f"IP Address: {net['ip']}")
                            st.write(f"Netmask: {net['netmask']}")
                            st.write(f"Network: {net['network']}")
                            st.write(f"Broadcast: {net['broadcast']}")
                
                if st.button("Scan Network"):
                    with st.spinner("Scanning network..."):
                        progress_bar = st.progress(0)
                        # Use the modified scan_network function that returns fake devices
                        st.session_state.active_devices = scan_network(network_address, progress_bar)
                        st.success(f"Found {len(st.session_state.active_devices)} active devices")
            
            if st.session_state.active_devices:
                st.subheader("Active Devices")
                
                # Create tabs for different views
                tab1, tab2 = st.tabs(["Device List", "Network Topology"])
                
                with tab1:
                    # Convert to DataFrame for better display
                    df = pd.DataFrame([
                        {
                            'IP': device.get('ip', 'Unknown'),
                            'Hostname': device.get('hostname', 'Unknown'),
                            'Response Time (ms)': f"{device.get('response_time', 0)*1000:.2f}",
                            'MAC Address': device.get('mac', 'Unknown'),
                            'Device Type': device.get('device_type', 'Unknown'),
                            'OS': device.get('os', 'Unknown'),
                            'Open Ports': ", ".join([f"{port}:{service}" for port, service in device.get('open_ports', {}).items()])
                        }
                        for device in st.session_state.active_devices
                    ])
                st.dataframe(df)
                
                with tab2:
                                # Create network graph
                    G = nx.Graph()
                    
                    # Add nodes for the router (assumed to be the local machine) and active devices
                    local_ip = next(net['ip'] for net in fake_networks if net['network'] == network_address)
                    G.add_node(local_ip, name="Local Machine", type="router", os="Local OS")
                
                    for device in st.session_state.active_devices:
                        G.add_node(
                            device.get('ip', 'Unknown'),
                            name=device.get('hostname', 'Unknown'),
                            type=device.get('device_type', 'Unknown'),
                            os=device.get('os', 'Unknown')
                        )
                        G.add_edge(local_ip, device.get('ip', 'Unknown'))
                
                    # Create positions for nodes
                    pos = nx.spring_layout(G)
                    
                    # Create a figure
                    fig, ax = plt.subplots(figsize=(10, 6))
                    
                    # Draw the nodes with different colors based on device type
                    node_colors = []
                    for node in G.nodes():
                        if node == local_ip:
                            node_colors.append('red')
                        else:
                            device_type = G.nodes[node]['type']
                            if device_type == 'router':
                                node_colors.append('red')
                            elif device_type == 'printer':
                                node_colors.append('blue')
                            elif device_type == 'computer':
                                node_colors.append('green')
                            else:
                                node_colors.append('gray')
                    
                    nx.draw_networkx_nodes(G, pos, node_size=500, node_color=node_colors, ax=ax)
                
                    # Draw the edges
                    nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5, ax=ax)
                    
                    # Draw the labels with more information
                    labels = {
                        node: f"{G.nodes[node]['name']}\n{node}\n{G.nodes[node]['type']}\n{G.nodes[node]['os']}"
                        for node in G.nodes()
                    }
                    nx.draw_networkx_labels(G, pos, labels, font_size=8, ax=ax)
                    
                    # Remove axis
                    plt.axis('off')
                    
                    # Display the graph
                    st.pyplot(fig)
        
        elif menu == "Performance Monitoring":
            st.title("Network Performance Monitoring")
            
            # Initialize result variables to avoid UnboundLocalError
            latency_result = None
            qos_result = None
            traffic_data = None
            bandwidth_data = None
            
            # Create tabs for different monitoring aspects
            tab1, tab2, tab3 = st.tabs(["Device Monitoring", "Traffic Analysis", "QoS Monitoring"])
            
            with tab1:
                st.subheader("Device Monitoring")
                
                # Check if we have active devices
                if not st.session_state.active_devices:
                    st.warning("No devices detected. Please run a network scan first.")
                    if st.button("Go to Network Discovery"):
                        st.session_state["menu"] = "Network Discovery"
                        st.rerun()
                else:
                    # Display list of devices for monitoring
                    options = []
                    for device in st.session_state.active_devices:
                        if isinstance(device, tuple):
                            ip = device[0]
                            hostname = device[2]
                        else:
                            ip = device['ip']
                            hostname = device['hostname']
                        options.append(f"{ip} ({hostname})")
                    
                    selected_device = st.selectbox("Select a device to monitor", options)
                    
                    if selected_device:
                        selected_ip = selected_device.split(' ')[0]
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            if st.button("Measure Latency"):
                                with st.spinner("Measuring latency..."):
                                    # Use fake monitoring data
                                    fake_data = generate_fake_monitoring_data()
                                    latency_result = fake_data['latency']
                        
                        with col2:
                            if st.button("Monitor QoS"):
                                with st.spinner("Monitoring QoS..."):
                                    # Use fake monitoring data
                                    fake_data = generate_fake_monitoring_data()
                                    qos_result = fake_data['qos']
                        
                    # Check if results exist before displaying
                    if latency_result:
                        st.success(f"Latency measured: {latency_result['avg']:.2f} ms")
                        st.info(f"Min: {latency_result['min']:.2f} ms, Max: {latency_result['max']:.2f} ms")
                        st.info(f"Packet Loss: {latency_result['packet_loss']:.1f}%")
                    
                    if qos_result:
                        st.success(f"Average Latency: {sum(qos_result['latency'])/len(qos_result['latency']):.2f} ms")
                        st.success(f"Jitter: {qos_result['jitter']:.2f} ms")
                        st.success(f"Bandwidth: {qos_result['bandwidth']:.2f} KB/s")
            
            with tab2:
                st.subheader("Traffic Analysis")
                
                # Select network interface for packet capture
                interfaces = ['Wi-Fi', 'Ethernet', 'Virtual Network']
                interface = st.selectbox("Select network interface", interfaces)
                
                if st.button("Start Packet Capture"):
                    with st.spinner("Capturing packets..."):
                        # Use fake monitoring data
                        fake_data = generate_fake_monitoring_data()
                        traffic_data = fake_data['traffic']
                        
                        # Display traffic analysis
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Total Packets", traffic_data['total_packets'])
                        col2.metric("Total Bytes", f"{traffic_data['total_bytes']/1024:.2f} KB")
                        col3.metric("Protocols", len(traffic_data['protocols']))
                        
                        # Display protocol distribution
                        if traffic_data['protocols']:
                            st.subheader("Protocol Distribution")
                            protocol_df = pd.DataFrame(
                                list(traffic_data['protocols'].items()),
                                columns=['Protocol', 'Count']
                            )
                            fig, ax = plt.subplots(figsize=(8, 4))
                            protocol_df.plot(kind='bar', x='Protocol', y='Count', ax=ax)
                            plt.xticks(rotation=45)
                            st.pyplot(fig)
                        
                        # Display top talkers
                        if traffic_data['top_talkers']:
                            st.subheader("Top Talkers")
                            talker_df = pd.DataFrame(
                                list(traffic_data['top_talkers'].items()),
                                columns=['IP', 'Bytes']
                            ).sort_values('Bytes', ascending=False)
                            st.dataframe(talker_df)
            
            with tab3:
                st.subheader("QoS Monitoring")
                
                # Real-time bandwidth monitoring
                if st.button("Start/Update Bandwidth Monitoring"):
                    # Use fake monitoring data
                    fake_data = generate_fake_monitoring_data()
                    bandwidth_data = fake_data['bandwidth']
                    
                    # Update bandwidth history
                    st.session_state.bandwidth_history = bandwidth_data['history']
                    st.session_state.prev_bandwidth_stats = {
                        'timestamp': datetime.now(),
                        'bytes_sent': 1000000,
                        'bytes_recv': 2000000
                    }
                    
                    # Check for bandwidth alerts
                    if bandwidth_data['download_speed'] > 2000:  # 2 MB/s
                        st.warning("High download bandwidth usage detected!")
                    if bandwidth_data['upload_speed'] > 1000:  # 1 MB/s
                        st.warning("High upload bandwidth usage detected!")
                    
                    st.success("Bandwidth stats updated")
            
            # Display bandwidth results if available
            if st.session_state.bandwidth_history:
                st.subheader("Bandwidth Analysis")
                
                # Get the latest measurement
                latest = st.session_state.bandwidth_history[-1]
                
                col1, col2 = st.columns(2)
                col1.metric("Download Speed", f"{latest['download_speed']:.2f} KB/s")
                col2.metric("Upload Speed", f"{latest['upload_speed']:.2f} KB/s")
                
                # Create chart if we have enough data points
                if len(st.session_state.bandwidth_history) > 1:
                    df = pd.DataFrame(st.session_state.bandwidth_history)
                    
                    # Plot bandwidth trend
                    fig, ax = plt.subplots(figsize=(10, 4))
                    ax.plot(df['timestamp'], df['download_speed'], marker='o', linestyle='-', color='blue', label='Download')
                    ax.plot(df['timestamp'], df['upload_speed'], marker='x', linestyle='--', color='green', label='Upload')
                    ax.set_ylabel('Speed (KB/s)')
                    ax.set_title('Bandwidth Utilization')
                    ax.legend()
                    ax.grid(True)
                    st.pyplot(fig)
        
        elif menu == "University Network Monitoring":
            university_network_monitoring()

def university_network_monitoring():
    """University network monitoring interface."""
    st.title("University Network Monitoring System")
    
    # Generate university network data
    admin_switches, distribution_switches, access_points = generate_university_network_data()
    
    # Summary metrics
    total_switches = len(admin_switches) + len(distribution_switches)
    active_switches = sum(1 for sw in admin_switches + distribution_switches if sw['status'] == 'active')
    total_aps = len(access_points)
    active_aps = sum(1 for ap in access_points if ap['status'] == 'active')
    
    # Display summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Switches", total_switches, f"{active_switches} active")
    col2.metric("Switch Uptime", f"{active_switches/total_switches*100:.1f}%")
    col3.metric("Total Access Points", total_aps, f"{active_aps} active")
    col4.metric("AP Uptime", f"{active_aps/total_aps*100:.1f}%")
    
    # Create tabs for different views
    tab1, tab2, tab3 = st.tabs(["Network Overview", "Switch Management", "Access Point Status"])
    
    with tab1:
        st.subheader("Network Overview")
        
        # Create network visualization
        G = nx.DiGraph()
        
        # Add nodes for admin switches
        for switch in admin_switches:
            G.add_node(switch['id'], 
                       name=switch['name'], 
                       type='admin_switch',
                       status=switch['status'],
                       ip=switch['ip'],
                       layer=0)  # Core layer
        
        # Add nodes for distribution switches and connect to admin switches
        for switch in distribution_switches:
            G.add_node(switch['id'], 
                       name=switch['name'], 
                       type='distribution_switch',
                       status=switch['status'],
                       ip=switch['ip'],
                       layer=1)  # Distribution layer
            G.add_edge(switch['connected_to'], switch['id'])
        
        # Add nodes for access points and connect to distribution switches
        for ap in access_points:
            G.add_node(ap['id'], 
                       name=ap['name'], 
                       type='access_point',
                       status=ap['status'],
                       ip=ap['ip'],
                       layer=2)  # Access layer
            G.add_edge(ap['connected_to'], ap['id'])
        
        # Create positions using a hierarchical layout
        try:
            # Use layer attribute for multipartite layout
            pos = nx.multipartite_layout(G, subset_key='layer')
        except:
            # Fallback to spring layout if multipartite fails
            st.warning("Falling back to alternative layout due to visualization error")
            pos = nx.spring_layout(G)
        
        # Create a figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Node colors based on type and status
        node_colors = []
        for node in G.nodes():
            node_type = G.nodes[node]['type']
            status = G.nodes[node]['status']
            
            if status != 'active':
                node_colors.append('red')  # Inactive devices are red
            elif node_type == 'admin_switch':
                node_colors.append('blue')
            elif node_type == 'distribution_switch':
                node_colors.append('green')
            else:  # access_point
                node_colors.append('orange')
        
        # Node sizes based on type
        node_sizes = []
        for node in G.nodes():
            node_type = G.nodes[node]['type']
            if node_type == 'admin_switch':
                node_sizes.append(500)
            elif node_type == 'distribution_switch':
                node_sizes.append(300)
            else:  # access_point
                node_sizes.append(100)
        
        # Draw the nodes
        nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.8, ax=ax)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5, edge_color='gray', arrows=True, arrowsize=15, ax=ax)
        
        # Draw labels with just the IDs to avoid clutter
        nx.draw_networkx_labels(G, pos, font_size=8, ax=ax)
        
        # Add a legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Admin Switch'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='Distribution Switch'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', markersize=10, label='Access Point'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Inactive Device')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        # Remove axis
        plt.axis('off')
        
        # Set title
        plt.title("University Network Topology")
        
        # Display the graph
        st.pyplot(fig)
        
        # Display critical alerts
        st.subheader("Critical Alerts")
        alerts = []
        
        for switch in admin_switches + distribution_switches:
            if switch['status'] != 'active':
                alerts.append(f"⚠️ Switch {switch['name']} ({switch['id']}) is DOWN")
        
        for ap in access_points:
            if ap['status'] != 'active':
                switch_name = next((s['name'] for s in distribution_switches if s['id'] == ap['connected_to']), 'Unknown')
                connected_switch_status = next((s['status'] for s in distribution_switches if s['id'] == ap['connected_to']), 'unknown')
                
                if connected_switch_status == 'active':
                    alerts.append(f"⚠️ Access Point {ap['name']} is DOWN (connected to active switch {switch_name})")
        
        if alerts:
            for alert in alerts[:5]:  # Show only top 5 alerts
                st.error(alert)
            if len(alerts) > 5:
                st.warning(f"{len(alerts) - 5} more alerts not shown")
        else:
            st.success("No critical alerts at this time")
    
    with tab2:
        st.subheader("Switch Management")
        
        # Combine all switches for selection
        all_switches = admin_switches + distribution_switches
        switch_options = [f"{switch['id']} - {switch['name']} ({switch['status'].upper()})" for switch in all_switches]
        selected_switch = st.selectbox("Select Switch", switch_options)
        
        if selected_switch:
            switch_id = selected_switch.split(' - ')[0]
            switch = next((s for s in all_switches if s['id'] == switch_id), None)
            
            if switch:
                # Display switch information
                cols = st.columns(2)
                with cols[0]:
                    st.subheader(f"{switch['name']} ({switch['id']})")
                    st.write(f"**IP Address:** {switch['ip']}")
                    st.write(f"**Location:** {switch['location']}")
                    st.write(f"**Model:** {switch['model']}")
                    
                    # Status indicator
                    if switch['status'] == 'active':
                        st.success("Status: ACTIVE")
                    else:
                        st.error("Status: INACTIVE")
                    
                    st.write(f"**Uptime:** {switch['uptime']}")
                    st.write(f"**Firmware:** {switch['firmware']}")
                
                with cols[1]:
                    st.subheader("Performance")
                    
                    # Use Plotly for performance metrics
                    cpu_load_value = float(switch['cpu_load'].strip('%')) / 100
                    memory_usage_value = float(switch['memory_usage'].strip('%')) / 100
                    
                    # Create gauge charts for CPU and memory
                    fig = make_subplots(
                        rows=2, cols=1,
                        specs=[[{"type": "indicator"}], [{"type": "indicator"}]],
                        vertical_spacing=0.2
                    )
                    
                    fig.add_trace(
                        go.Indicator(
                            mode="gauge+number",
                            value=cpu_load_value * 100,
                            title={"text": "CPU Load"},
                            gauge={
                                'axis': {'range': [0, 100]},
                                'bar': {'color': "darkblue"},
                                'steps': [
                                    {'range': [0, 30], 'color': "green"},
                                    {'range': [30, 70], 'color': "yellow"},
                                    {'range': [70, 100], 'color': "red"},
                                ],
                                'threshold': {
                                    'line': {'color': "red", 'width': 4},
                                    'thickness': 0.75,
                                    'value': 90
                                }
                            }
                        ),
                        row=1, col=1
                    )
                    
                    fig.add_trace(
                        go.Indicator(
                            mode="gauge+number",
                            value=memory_usage_value * 100,
                            title={"text": "Memory Usage"},
                            gauge={
                                'axis': {'range': [0, 100]},
                                'bar': {'color': "darkblue"},
                                'steps': [
                                    {'range': [0, 30], 'color': "green"},
                                    {'range': [30, 70], 'color': "yellow"},
                                    {'range': [70, 100], 'color': "red"},
                                ],
                                'threshold': {
                                    'line': {'color': "red", 'width': 4},
                                    'thickness': 0.75,
                                    'value': 90
                                }
                            }
                        ),
                        row=2, col=1
                    )
                    
                    fig.update_layout(
                        height=400,
                        margin=dict(l=20, r=20, t=30, b=20)
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.write(f"**Ports:** {switch['active_ports']}/{switch['ports']} active")
                    
                    # Create port status visualization with Plotly
                    port_status = [1] * switch['active_ports'] + [0] * (switch['ports'] - switch['active_ports'])
                    port_numbers = list(range(1, switch['ports'] + 1))
                    
                    port_fig = go.Figure()
                    
                    # Add active ports
                    active_ports = port_numbers[:switch['active_ports']]
                    port_fig.add_trace(go.Bar(
                        x=active_ports,
                        y=[1] * len(active_ports),
                        name='Active',
                        marker_color='green'
                    ))
                    
                    # Add inactive ports
                    inactive_ports = port_numbers[switch['active_ports']:]
                    if inactive_ports:
                        port_fig.add_trace(go.Bar(
                            x=inactive_ports,
                            y=[1] * len(inactive_ports),
                            name='Inactive',
                            marker_color='red'
                        ))
                    
                    port_fig.update_layout(
                        title="Port Status",
                        xaxis_title="Port Number",
                        yaxis=dict(
                            showticklabels=False,
                            showgrid=False
                        ),
                        barmode='stack',
                        height=200,
                        showlegend=True,
                        margin=dict(l=20, r=20, t=40, b=20)
                    )
                    
                    st.plotly_chart(port_fig, use_container_width=True)
                
                # Connected devices
                st.subheader("Connected Devices")
                
                # Distribution switches connected to admin switches
                if 'CORE' in switch['id']:
                    connected_switches = [s for s in distribution_switches if s['connected_to'] == switch['id']]
                    if connected_switches:
                        st.write(f"Connected Distribution Switches: {len(connected_switches)}")
                        switch_data = []
                        for s in connected_switches:
                            switch_data.append({
                                "ID": s['id'],
                                "Name": s['name'],
                                "IP": s['ip'],
                                "Status": s['status'].upper(),
                                "Location": s['location'],
                                "Uptime": s['uptime']
                            })
                        st.dataframe(pd.DataFrame(switch_data))
                    else:
                        st.write("No distribution switches connected")
                
                # Access points connected to distribution switches
                if '-SW-' in switch['id'] and 'CORE' not in switch['id']:
                    connected_aps = [ap for ap in access_points if ap['connected_to'] == switch['id']]
                    if connected_aps:
                        st.write(f"Connected Access Points: {len(connected_aps)}")
                        ap_data = []
                        for ap in connected_aps:
                            ap_data.append({
                                "ID": ap['id'],
                                "Name": ap['name'],
                                "IP": ap['ip'],
                                "Status": ap['status'].upper(),
                                "Location": ap['location'],
                                "Connected Clients": ap['connected_clients']
                            })
                        st.dataframe(pd.DataFrame(ap_data))
                    else:
                        st.write("No access points connected")
                
                # Actions
                st.subheader("Actions")
                col1, col2, col3 = st.columns(3)
                with col1:
                    restart_btn = st.button("Restart Switch")
                    if restart_btn:
                        st.info("Simulated: Restart command sent to switch")
                
                with col2:
                    update_btn = st.button("Update Firmware")
                    if update_btn:
                        st.info("Simulated: Firmware update initiated")
                
                with col3:
                    backup_btn = st.button("Backup Configuration")
                    if backup_btn:
                        st.info("Simulated: Configuration backup started")
    
    with tab3:
        st.subheader("Access Point Status")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            building_filter = st.multiselect("Filter by Building", 
                                           list(set([ap['name'].split('-')[0] for ap in access_points])),
                                           default=[])
        with col2:
            status_filter = st.selectbox("Filter by Status", ["All", "Active", "Inactive"], index=0)
        
        # Apply filters
        filtered_aps = access_points
        if building_filter:
            filtered_aps = [ap for ap in filtered_aps if any(code in ap['name'] for code in building_filter)]
        
        if status_filter != "All":
            filtered_aps = [ap for ap in filtered_aps if ap['status'].lower() == status_filter.lower()]
        
        # Display AP table
        if filtered_aps:
            ap_data = []
            for ap in filtered_aps:
                ap_data.append({
                    "ID": ap['id'],
                    "Name": ap['name'],
                    "Location": ap['location'],
                    "IP": ap['ip'],
                    "Status": ap['status'].upper(),
                    "Connected To": ap['connected_to'],
                    "Clients": ap['connected_clients'],
                    "Channel": ap['channel'],
                    "Signal": ap['signal_strength']
                })
            
            st.dataframe(pd.DataFrame(ap_data))
            
            # Display AP statistics
            st.subheader("Access Point Statistics")
            
            # Total clients connected
            total_clients = sum(ap['connected_clients'] for ap in filtered_aps if ap['status'] == 'active')
            st.metric("Total Connected Clients", total_clients)
            
            # Distribution of clients by building
            if filtered_aps:
                st.subheader("Client Distribution by Building")
                building_clients = {}
                for ap in filtered_aps:
                    if ap['status'] == 'active':
                        building_code = ap['name'].split('-')[0]
                        if building_code not in building_clients:
                            building_clients[building_code] = 0
                        building_clients[building_code] += ap['connected_clients']
                
                if building_clients:
                    fig, ax = plt.subplots(figsize=(10, 6))
                    buildings = list(building_clients.keys())
                    clients = list(building_clients.values())
                    ax.bar(buildings, clients)
                    ax.set_xlabel("Building")
                    ax.set_ylabel("Connected Clients")
                    ax.set_title("Client Distribution by Building")
                    st.pyplot(fig)
                else:
                    st.write("No client data available for the selected filters")
        else:
            st.write("No access points found matching the selected filters")

if __name__ == "__main__":
    main()
