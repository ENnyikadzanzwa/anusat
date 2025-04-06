# Network Analysis Tool

A comprehensive network analysis and monitoring tool built with Python and Streamlit. This tool provides real-time network discovery, device monitoring, and performance analysis capabilities.

## Features

### 1. Network Discovery
- Automatic network interface detection
- Real-time device scanning
- Detailed device information including:
  - IP addresses
  - MAC addresses
  - Open ports and services
  - Operating systems
  - Device types
- Interactive network topology visualization
- Device categorization (routers, switches, computers, IoT devices, etc.)

### 2. Performance Monitoring
- Real-time latency measurement
- Quality of Service (QoS) monitoring
- Bandwidth utilization tracking
- Traffic analysis including:
  - Protocol distribution
  - Top talkers
  - Packet statistics
- Historical data visualization

### 3. Security Features
- User authentication system
- Secure session management
- Role-based access control
- Activity logging

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Nmap (optional, for enhanced scanning capabilities)

### Required Python Packages
```bash
pip install streamlit
pip install pandas
pip install numpy
pip install matplotlib
pip install networkx
pip install ping3
pip install psutil
pip install netifaces
pip install scapy
```

### Optional Dependencies
```bash
pip install python-nmap  # For enhanced scanning capabilities
```

## Usage

1. Start the application:
```bash
streamlit run main.py
```

2. Login with your credentials or register a new account

3. Navigate through the interface:
   - Network Discovery: Scan and visualize your network
   - Performance Monitoring: Track network performance metrics

## Project Structure

```
network_analysis/
├── main.py                 # Main application file
├── README.md               # Project documentation
├── requirements.txt        # Python dependencies
└── user_credentials.pkl    # User authentication data
```

## Device Categories

The tool recognizes and categorizes the following device types:

1. Network Infrastructure
   - Routers
   - Switches
   - Access Points

2. Computers and Workstations
   - Windows PCs
   - Linux Servers
   - Mac Computers

3. Mobile Devices
   - Smartphones
   - Tablets

4. IoT Devices
   - Smart TVs
   - Security Cameras
   - Smart Thermostats
   - Smart Bulbs

5. Printers and Scanners
   - Network Printers
   - Document Scanners

6. Servers
   - Web Servers
   - Database Servers
   - File Servers

7. Virtual Machines
   - Web VMs
   - Database VMs

## Monitoring Metrics

### Latency Monitoring
- Minimum latency
- Maximum latency
- Average latency
- Packet loss percentage

### QoS Metrics
- Jitter
- Bandwidth utilization
- Protocol distribution
- Connection quality

### Traffic Analysis
- Total packets
- Total bytes
- Protocol counts
- Top talkers
- Network utilization

## Security Considerations

1. Authentication
   - Secure password storage using SHA-256 hashing
   - Session management
   - Automatic logout

2. Network Security
   - Safe scanning practices
   - Rate limiting
   - Error handling

3. Data Protection
   - Secure storage of credentials
   - Encrypted session data
   - Access control

## Limitations

1. Network Scanning
   - Basic scanning without Nmap
   - Limited OS detection capabilities
   - Rate-limited to prevent network congestion

2. Performance Monitoring
   - Limited to available network interfaces
   - Basic QoS metrics without specialized hardware
   - Approximate bandwidth measurements

## Future Enhancements

1. Network Features
   - VLAN support
   - Wireless network analysis
   - Advanced protocol analysis
   - Custom scanning profiles

2. Monitoring Features
   - Real-time alerts
   - Custom monitoring dashboards
   - Historical data analysis
   - Export capabilities

3. Security Features
   - Vulnerability scanning
   - Security recommendations
   - Compliance reporting
   - Advanced authentication options

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Streamlit for the web interface framework
- NetworkX for network visualization
- Python community for various libraries and tools

## Support

For support, please open an issue in the GitHub repository or contact the development team.

## Version History

- 1.0.0 (2024-03-20)
  - Initial release
  - Basic network discovery
  - Performance monitoring
  - User authentication 