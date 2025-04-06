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