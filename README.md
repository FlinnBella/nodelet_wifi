# nodelet_wifi
Integraton of Wifi services with nodelet; give users options to run tasks on rpi. 


# Bluetooth Pi Scraping Setup Guide

## 🍓 Raspberry Pi Server Setup

### 1. System Requirements
- Raspberry Pi 3/4/5 with Bluetooth
- Raspbian OS (Bullseye or newer)
- Internet connection for initial setup
- 8GB+ SD card

### 2. Quick Setup Script
```bash
# Download and run setup script
curl -sSL https://raw.githubusercontent.com/your-repo/bluetooth-setup.sh | bash

# Or manual setup:
sudo apt update && sudo apt upgrade -y
sudo apt install -y bluetooth bluez bluez-tools python3-bluetooth python3-dev libbluetooth-dev
```

### 3. Server Installation
```bash
# Create project directory
sudo mkdir -p /opt/pi-bluetooth-scraper
cd /opt/pi-bluetooth-scraper

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r server_requirements.txt

# Copy server code
cp bluetooth_server.py .
chmod +x bluetooth_server.py

# Start server
python3 bluetooth_server.py
```

### 4. Enable Auto-Start (Optional)
```bash
# Create systemd service
sudo tee /etc/systemd/system/bluetooth-scraper.service > /dev/null << EOF
[Unit]
Description=Bluetooth Pi Scraping Server
After=bluetooth.service

[Service]
Type=simple
User=pi
WorkingDirectory=/opt/pi-bluetooth-scraper
Environment=PATH=/opt/pi-bluetooth-scraper/venv/bin
ExecStart=/opt/pi-bluetooth-scraper/venv/bin/python bluetooth_server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable bluetooth-scraper
sudo systemctl start bluetooth-scraper
```

## 📱 Client Setup (Any Device)

### 1. Requirements
- Python 3.7+
- Bluetooth capability
- Linux/Windows/macOS

### 2. Installation

#### Linux (Ubuntu/Debian)
```bash
# Install system Bluetooth libraries
sudo apt install -y bluetooth bluez python3-dev libbluetooth-dev

# Install Python client
pip3 install -r client_requirements.txt
```

#### Windows
```bash
# Install Python Bluetooth library
pip install pybluez

# May need Microsoft Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

#### macOS
```bash
# Install using Homebrew
brew install python3
pip3 install pybluez

# Note: macOS has built-in Bluetooth support
```

### 3. Client Usage
```bash
# Discover and connect to nearby Pi servers
python3 bluetooth_client.py --discover

# Connect directly to known address
python3 bluetooth_client.py --address AA:BB:CC:DD:EE:FF

# Single URL scraping
python3 bluetooth_client.py --discover --url https://example.com

# PubMed search
python3 bluetooth_client.py --discover --pubmed "machine learning"

# Health check
python3 bluetooth_client.py --discover --health
```

## 🔧 Configuration

### Server Configuration
The server automatically:
- Makes Bluetooth discoverable
- Advertises "Pi-Scraper-BT" service
- Handles multiple concurrent connections
- Implements rate limiting (30 requests/minute per device)
- Manages sessions (1 hour timeout)

### Client Configuration
```python
# Optional: Create config file ~/.pi-scraper-client.json
{
    "default_timeout": 30,
    "max_retries": 3,
    "auto_discover": true,
    "preferred_services": ["Pi-Scraper-BT"]
}
```

## 🔐 Security Features

### Built-in Protection
- **Session Management**: Unique tokens per device
- **Rate Limiting**: 30 requests/minute per device
- **Device Limiting**: Max 3 sessions per device
- **Session Timeout**: 1-hour automatic cleanup
- **Request Validation**: JSON schema validation

### Network Security
- **No Internet Required**: Bluetooth operates locally
- **Anonymous Access**: No user registration needed
- **Encrypted Communication**: Bluetooth encryption
- **No Data Storage**: No personal data retained

## 📡 Network Topology

```
[Client Device] ←→ [Bluetooth] ←→ [Raspberry Pi] ←→ [Internet] ←→ [Target Websites]
      |                                |                            |
   Your Device                    Pi's IP Address              Scraped Data
   (Anonymous)                    (Your Location)             (Anonymous to you)
```

## ⚡ Performance

### Bluetooth Limitations
- **Range**: ~10 meters (30 feet)
- **Bandwidth**: ~1-3 Mbps (sufficient for text data)
- **Latency**: ~100-500ms (higher than WiFi)
- **Concurrent**: ~5-7 simultaneous connections

### Optimizations
- **Chunked Responses**: Large data split into 1KB chunks
- **Session Reuse**: Persistent connections
- **Rate Limiting**: Prevents overload
- **Compression**: JSON responses minimized

## 🐛 Troubleshooting

### Server Issues
```bash
# Check Bluetooth status
sudo systemctl status bluetooth
hciconfig hci0

# Check service logs
sudo journalctl -u bluetooth-scraper -f

# Reset Bluetooth
sudo systemctl restart bluetooth
sudo hciconfig hci0 down && sudo hciconfig hci0 up
```

### Client Issues
```bash
# Check Bluetooth devices
bluetoothctl
> scan on
> devices

# Python Bluetooth test
python3 -c "import bluetooth; print(bluetooth.discover_devices())"

# Permission issues (Linux)
sudo usermod -a -G bluetooth $USER
# Log out and back in
```

### Connection Problems
1. **Can't discover services**: Check if Pi is discoverable
2. **Connection refused**: Ensure server is running
3. **Session expired**: Reconnect to get new session
4. **Rate limited**: Wait 1 minute and retry

## 🚀 Advanced Usage

### Multiple Pi Network
Deploy multiple Pis for redundancy:
```bash
# Each Pi gets unique name
Pi-Scraper-BT-01
Pi-Scraper-BT-02
Pi-Scraper-BT-03
```

### Custom Scraping
```python
# Example: Custom selectors
selectors = {
    "titles": "h1, h2, h3",
    "prices": ".price, .cost",
    "descriptions": ".description, .summary"
}

result = client.scrape_url(
    "https://example.com",
    selectors=selectors,
    extract_links=True
)
```

### Batch Processing
```python
# Scrape multiple URLs
urls = [
    {"url": "https://site1.com", "extract_links": True},
    {"url": "https://site2.com", "selectors": {"title": "h1"}},
    {"url": "https://site3.com", "extract_images": True}
]

results = client.scrape_multiple(urls)
```

## 💡 Use Cases

### Research
- **Academic**: Gather research papers from PubMed
- **Market**: Monitor competitor websites
- **News**: Collect articles from multiple sources
- **Legal**: Research case law and regulations
- **Medical**: Aggregate health information

### Business Intelligence
- **Price Monitoring**: Track competitor pricing
- **Product Research**: Analyze product reviews
- **Social Sentiment**: Monitor brand mentions
- **Job Market**: Track hiring trends
- **Real Estate**: Monitor property listings

### Privacy-Focused Use Cases
- **Anonymous Browsing**: Access websites through Pi's IP
- **Geo-Restriction Bypass**: Use Pi's location
- **Research Protection**: Hide your research interests
- **Competitor Analysis**: Avoid detection while monitoring
- **Data Collection**: Gather data without exposing your identity

## 🌐 Deployment Scenarios

### Single Pi Setup
```
Home Network:
[Router] ←→ [Raspberry Pi] ←→ [Your Devices via Bluetooth]
```

### Multi-Pi Mesh Network
```
Coverage Area:
[Pi-01] ←→ [Pi-02] ←→ [Pi-03]
   ↕         ↕         ↕
[Clients] [Clients] [Clients]
```

### Mobile Deployment
```
Vehicle/Portable:
[Power Bank] → [Raspberry Pi Zero W] ←→ [Mobile Devices]
```

## 📊 Monitoring & Analytics

### Server Metrics
```bash
# Check active sessions
curl -X POST -d '{"type":"health_check"}' localhost:8888

# Monitor resource usage
htop
iotop
```

### Usage Statistics
The server tracks:
- Active sessions per device
- Requests per minute/hour
- Success/failure rates
- Data transfer volumes
- Popular scraping targets

### Log Analysis
```bash
# Server logs
tail -f /var/log/bluetooth-scraper.log

# Connection logs
journalctl -u bluetooth -f

# System performance
dmesg | grep bluetooth
```

## 🔄 Scaling Strategies

### Horizontal Scaling
Deploy multiple Pi devices:
- **Geographic**: Different physical locations
- **Load Distribution**: Balance across multiple Pis
- **Redundancy**: Backup if one Pi fails
- **Specialization**: Different Pis for different tasks

### Vertical Scaling
Upgrade individual Pis:
- **Pi 4 8GB**: More concurrent connections
- **Fast SD Cards**: Better I/O performance
- **Ethernet**: Faster internet connection
- **External Storage**: More caching capacity

### Network Optimization
```bash
# Optimize Bluetooth settings
echo 'Class=0x000100' >> /etc/bluetooth/main.conf
echo 'DiscoverableTimeout=0' >> /etc/bluetooth/main.conf

# Increase connection limits
echo 'MaxConnections=10' >> /etc/bluetooth/main.conf
```

## 🛡️ Advanced Security

### Access Control Lists
```python
# Whitelist specific devices
ALLOWED_DEVICES = {
    "AA:BB:CC:DD:EE:FF": "My Phone",
    "11:22:33:44:55:66": "My Laptop"
}

# Device-specific rate limits
DEVICE_LIMITS = {
    "AA:BB:CC:DD:EE:FF": 100,  # requests/hour
    "default": 30
}
```

### Encryption
```python
# Add message encryption
from cryptography.fernet import Fernet

class SecureBluetoothServer:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
    
    def encrypt_message(self, message: str) -> bytes:
        return self.cipher.encrypt(message.encode())
    
    def decrypt_message(self, encrypted: bytes) -> str:
        return self.cipher.decrypt(encrypted).decode()
```

### Audit Logging
```python
import logging

# Security audit log
security_logger = logging.getLogger('security')
security_logger.addHandler(logging.FileHandler('/var/log/bt-security.log'))

# Log all connections
def log_connection(device_addr, device_name, action):
    security_logger.info(f"{action}: {device_name} ({device_addr})")
```

## 📈 Business Model Integration

### Cryptocurrency Payments
```python
# Example: Simple token system
class TokenManager:
    def __init__(self):
        self.token_rates = {
            'scrape_url': 0.001,      # 0.001 tokens per URL
            'scrape_pubmed': 0.005,   # 0.005 tokens per search
            'scrape_multiple': 0.003  # 0.003 tokens per URL
        }
    
    def calculate_cost(self, request_type: str, quantity: int = 1):
        return self.token_rates.get(request_type, 0) * quantity
```

### Usage-Based Billing
```python
# Track usage for billing
class UsageTracker:
    def log_usage(self, device_id, service_type, data_size, processing_time):
        usage_record = {
            'device_id': device_id,
            'service': service_type,
            'timestamp': time.time(),
            'data_bytes': data_size,
            'processing_ms': processing_time,
            'cost_tokens': self.calculate_cost(service_type)
        }
        self.save_usage_record(usage_record)
```

## 🔧 Customization Options

### Custom Scrapers
```python
# Add specialized scraping functions
class CustomScrapers:
    @staticmethod
    def scrape_social_media(platform: str, query: str):
        # Custom logic for social media scraping
        pass
    
    @staticmethod
    def scrape_ecommerce(site: str, product_query: str):
        # Custom e-commerce scraping
        pass
    
    @staticmethod
    def scrape_news(sources: List[str], keywords: List[str]):
        # Custom news aggregation
        pass
```

### Plugin System
```python
# Plugin architecture
class ScrapingPlugin:
    def __init__(self, name: str):
        self.name = name
    
    def process_request(self, request_data: Dict) -> Dict:
        raise NotImplementedError
    
    def get_capabilities(self) -> List[str]:
        raise NotImplementedError

# Load plugins dynamically
plugin_manager = PluginManager()
plugin_manager.load_plugins_from_directory('/opt/plugins/')
```

## 🌍 Global Deployment

### Multi-Region Setup
```bash
# Deploy across different regions
Region 1: Pi-Scraper-US-East
Region 2: Pi-Scraper-EU-West  
Region 3: Pi-Scraper-ASIA-Pacific
```

### Geolocation Services
```python
# Route requests based on target location
class GeoRouter:
    def route_request(self, target_url: str, client_location: str):
        # Determine best Pi based on target geography
        best_pi = self.find_nearest_pi(target_url, client_location)
        return best_pi.process_request(request)
```

### Load Balancing
```python
# Distribute requests across available Pis
class LoadBalancer:
    def __init__(self, pi_nodes: List[PiNode]):
        self.nodes = pi_nodes
        self.current_node = 0
    
    def get_next_node(self) -> PiNode:
        # Round-robin or weighted selection
        node = self.nodes[self.current_node]
        self.current_node = (self.current_node + 1) % len(self.nodes)
        return node
```

## 🎯 Next Steps

### Development Roadmap
1. **Phase 1**: Basic Bluetooth scraping (✓ Complete)
2. **Phase 2**: Add encryption and security
3. **Phase 3**: Implement payment system
4. **Phase 4**: Multi-Pi mesh networking
5. **Phase 5**: Mobile apps and GUI clients

### Community Building
- **GitHub Repository**: Open source the code
- **Documentation**: Comprehensive setup guides
- **Discord/Telegram**: Community support channels
- **Bounty Program**: Reward contributions

### Monetization Strategies
- **Hardware Sales**: Pre-configured Pi devices
- **Subscription Service**: Managed Pi networks
- **Enterprise Licensing**: Business-grade features
- **Consulting**: Custom deployment services

## 📞 Support & Resources

### Community
- **GitHub**: github.com/your-username/bluetooth-pi-scraper
- **Discord**: discord.gg/pi-scraper-community
- **Reddit**: r/RaspberryPiScraping
- **Telegram**: @PiScraperSupport

### Professional Services
- **Custom Development**: Tailored scraping solutions
- **Enterprise Deployment**: Large-scale implementations
- **Training Workshops**: Learn advanced techniques
- **24/7 Support**: Premium support packages

### Legal Considerations
- **Terms of Service**: Clear usage guidelines
- **Privacy Policy**: Data handling practices
- **Compliance**: GDPR, CCPA, and local regulations
- **Liability**: Limitation of liability clauses

---

## 🚀 Quick Start Summary

1. **Flash Raspberry Pi** with latest Raspbian
2. **Run setup script** to install dependencies
3. **Start Bluetooth server** on Pi
4. **Install client** on your device
5. **Discover and connect** via Bluetooth
6. **Start scraping** anonymously!

**Commands:**
```bash
# Pi Server
python3 bluetooth_server.py

# Client
python3 bluetooth_client.py --discover --url https://example.com
```

**That's it!** You now have a working anonymous Bluetooth scraping network. The Pi acts as your anonymous proxy, hiding your identity while you collect data from the web.

## 📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer
This software is for educational and research purposes. Users are responsible for complying with all applicable laws and website terms of service. The authors are not liable for any misuse of this software.