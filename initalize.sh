#!/bin/bash
# Raspberry Pi Web Scraping Server Setup Script

set -e

echo "🍓 Raspberry Pi Web Scraping Server Setup"
echo "========================================"

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv

# Install system dependencies for web scraping
echo "🔧 Installing system dependencies..."
sudo apt install -y \
    curl \
    wget \
    git \
    htop \
    ufw \
    fail2ban

# Create project directory
PROJECT_DIR="/opt/pi-scraping-server"
echo "📁 Creating project directory: $PROJECT_DIR"
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR

# Create virtual environment
echo "🌐 Creating Python virtual environment..."
cd $PROJECT_DIR
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "📚 Installing Python packages..."
pip install --upgrade pip
pip install requests beautifulsoup4 lxml

# Create requirements.txt
cat > requirements.txt << EOF
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
EOF

# Create server script
echo "📝 Creating server script..."
cat > server.py << 'EOF'
#!/usr/bin/env python3
"""
Raspberry Pi Web Scraping Server
Allows external users to connect and perform web scraping operations
"""

import socket
import threading
import json
import time
import hashlib
import hmac
import secrets
from typing import Dict, List, Optional, Tuple, Callable, Any
from dataclasses import dataclass
from enum import Enum
import requests
from bs4 import BeautifulSoup
import logging
from functools import wraps, reduce
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RequestType(Enum):
    SCRAPE_URL = "scrape_url"
    SCRAPE_MULTIPLE = "scrape_multiple"
    HEALTH_CHECK = "health_check"
    AUTH = "auth"
    SCRAPE_PUBMED = "scrape_pubmed"

@dataclass
class PubMedScrapeRequest:
    query: str
    max_results: int = 10

@dataclass
class ScrapeRequest:
    url: str
    selectors: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    timeout: int = 30
    extract_links: bool = False
    extract_images: bool = False

@dataclass
class ScrapeResult:
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    timestamp: float = None
    url: str = ""

class SecurityManager:
    """Handles authentication and rate limiting using functional approaches"""
    
    def __init__(self, max_requests_per_minute: int = 60):
        self.api_keys = set()
        self.request_history: Dict[str, List[float]] = {}
        self.max_requests_per_minute = max_requests_per_minute
        
    def generate_api_key(self) -> str:
        """Generate a secure API key"""
        return secrets.token_urlsafe(32)
    
    def add_api_key(self, key: str) -> None:
        """Add API key to authorized set"""
        self.api_keys.add(key)
    
    def validate_api_key(self, key: str) -> bool:
        """Validate API key"""
        return key in self.api_keys
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Check if client has exceeded rate limit using functional approach"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Filter requests from last minute
        recent_requests = list(filter(
            lambda timestamp: timestamp > minute_ago,
            self.request_history.get(client_id, [])
        ))
        
        # Update history
        self.request_history[client_id] = recent_requests
        
        return len(recent_requests) < self.max_requests_per_minute
    
    def log_request(self, client_id: str) -> None:
        """Log request timestamp"""
        if client_id not in self.request_history:
            self.request_history[client_id] = []
        self.request_history[client_id].append(time.time())

class WebScraper:
    """Functional web scraper with composable operations"""
    
    @staticmethod
    def create_session(headers: Optional[Dict[str, str]] = None) -> requests.Session:
        """Create configured session"""
        session = requests.Session()
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        session.headers.update(default_headers)
        if headers:
            session.headers.update(headers)
        return session
    
    @staticmethod
    def fetch_page(session: requests.Session, url: str, timeout: int = 30) -> Tuple[bool, Optional[str], Optional[str]]:
        """Fetch page content - pure function"""
        try:
            response = session.get(url, timeout=timeout)
            response.raise_for_status()
            return True, response.text, None
        except requests.RequestException as e:
            return False, None, str(e)
    
    @staticmethod
    def parse_html(html: str) -> BeautifulSoup:
        """Parse HTML content"""
        return BeautifulSoup(html, 'html.parser')
    
    @staticmethod
    def extract_by_selectors(soup: BeautifulSoup, selectors: Dict[str, str]) -> Dict[str, List[str]]:
        """Extract data using CSS selectors - pure function"""
        return {
            name: [elem.get_text(strip=True) for elem in soup.select(selector)]
            for name, selector in selectors.items()
        }
    
    @staticmethod
    def extract_links(soup: BeautifulSoup) -> List[str]:
        """Extract all links from page"""
        return [link.get('href') for link in soup.find_all('a', href=True)]
    
    @staticmethod
    def extract_images(soup: BeautifulSoup) -> List[str]:
        """Extract all image sources"""
        return [img.get('src') for img in soup.find_all('img', src=True)]
    
    @classmethod
    def scrape_url(cls, request: ScrapeRequest) -> ScrapeResult:
        """Main scraping function using functional composition"""
        session = cls.create_session(request.headers)
        
        # Fetch page
        success, html, error = cls.fetch_page(session, request.url, request.timeout)
        if not success:
            return ScrapeResult(
                success=False,
                data={},
                error=error,
                timestamp=time.time(),
                url=request.url
            )
        
        # Parse HTML
        soup = cls.parse_html(html)
        
        # Extract data using functional composition
        result_data = {}
        
        # Extract by selectors if provided
        if request.selectors:
            result_data['selected_data'] = cls.extract_by_selectors(soup, request.selectors)
        
        # Extract links if requested
        if request.extract_links:
            result_data['links'] = cls.extract_links(soup)
        
        # Extract images if requested
        if request.extract_images:
            result_data['images'] = cls.extract_images(soup)
        
        # Always include basic page info
        result_data['title'] = soup.title.string if soup.title else ""
        result_data['meta_description'] = ""
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            result_data['meta_description'] = meta_desc.get('content', '')
        
        return ScrapeResult(
            success=True,
            data=result_data,
            timestamp=time.time(),
            url=request.url
        )

    @classmethod
    def scrape_pubmed(cls, request: PubMedScrapeRequest) -> ScrapeResult:
        """Scrape PubMed for a given query"""
        base_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/"
        search_url = f"{base_url}esearch.fcgi"
        fetch_url = f"{base_url}efetch.fcgi"

        search_params = {
            "db": "pubmed",
            "term": request.query,
            "retmax": request.max_results,
            "retmode": "json"
        }

        try:
            search_response = requests.get(search_url, params=search_params)
            search_response.raise_for_status()
            search_data = search_response.json()
            
            id_list = search_data.get("esearchresult", {}).get("idlist", [])
            if not id_list:
                return ScrapeResult(
                    success=True,
                    data={"articles": []},
                    timestamp=time.time(),
                    url=search_url
                )

            fetch_params = {
                "db": "pubmed",
                "id": ",".join(id_list),
                "retmode": "xml"
            }

            fetch_response = requests.get(fetch_url, params=fetch_params)
            fetch_response.raise_for_status()
            
            soup = BeautifulSoup(fetch_response.text, 'xml')
            articles = []
            for article in soup.find_all("PubmedArticle"):
                title = article.find("ArticleTitle").text if article.find("ArticleTitle") else "No Title"
                abstract = article.find("AbstractText").text if article.find("AbstractText") else "No Abstract"
                articles.append({"title": title, "abstract": abstract})

            return ScrapeResult(
                success=True,
                data={"articles": articles},
                timestamp=time.time(),
                url=fetch_url
            )

        except requests.RequestException as e:
            return ScrapeResult(
                success=False,
                data={},
                error=str(e),
                timestamp=time.time(),
                url=search_url
            )

class ScrapingServer:
    """Main server class handling client connections"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8888):
        self.host = host
        self.port = port
        self.security_manager = SecurityManager()
        self.scraper = WebScraper()
        self.running = False
        
        # Generate and add default API key
        default_key = self.security_manager.generate_api_key()
        self.security_manager.add_api_key(default_key)
        logger.info(f"Default API Key: {default_key}")
    
    def add_api_key(self, key: str) -> None:
        """Add new API key"""
        self.security_manager.add_api_key(key)
        logger.info(f"Added API key: {key}")
    
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        """Handle individual client connection"""
        client_id = f"{address[0]}:{address[1]}"
        logger.info(f"Client connected: {client_id}")
        
        try:
            while True:
                # Receive data
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                # Process request
                response = self.process_request(data, client_id)
                
                # Send response
                client_socket.send(response.encode('utf-8'))
                
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            client_socket.close()
            logger.info(f"Client disconnected: {client_id}")
    
    def process_request(self, data: str, client_id: str) -> str:
        """Process incoming request using functional approach"""
        try:
            request_data = json.loads(data)
            request_type = request_data.get('type')
            api_key = request_data.get('api_key')
            
            # Validate API key
            if not self.security_manager.validate_api_key(api_key):
                return json.dumps({
                    'success': False,
                    'error': 'Invalid API key',
                    'timestamp': time.time()
                })
            
            # Check rate limit
            if not self.security_manager.check_rate_limit(client_id):
                return json.dumps({
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'timestamp': time.time()
                })
            
            # Log request
            self.security_manager.log_request(client_id)
            
            # Route request to appropriate handler
            response = self.route_request(request_type, request_data)
            
        except json.JSONDecodeError:
            response = {
                'success': False,
                'error': 'Invalid JSON format',
                'timestamp': time.time()
            }
        except Exception as e:
            response = {
                'success': False,
                'error': f'Server error: {str(e)}',
                'timestamp': time.time()
            }
        
        return json.dumps(response, default=str)
    
    def route_request(self, request_type: str, request_data: Dict) -> Dict:
        """Route request to appropriate handler"""
        handlers = {
            RequestType.SCRAPE_URL.value: self.handle_scrape_url,
            RequestType.SCRAPE_MULTIPLE.value: self.handle_scrape_multiple,
            RequestType.HEALTH_CHECK.value: self.handle_health_check,
            RequestType.SCRAPE_PUBMED.value: self.handle_scrape_pubmed,
        }
        
        handler = handlers.get(request_type)
        if not handler:
            return {
                'success': False,
                'error': f'Unknown request type: {request_type}',
                'timestamp': time.time()
            }
        
        return handler(request_data)
    
    def handle_scrape_url(self, request_data: Dict) -> Dict:
        """Handle single URL scraping request"""
        try:
            scrape_request = ScrapeRequest(
                url=request_data['url'],
                selectors=request_data.get('selectors'),
                headers=request_data.get('headers'),
                timeout=request_data.get('timeout', 30),
                extract_links=request_data.get('extract_links', False),
                extract_images=request_data.get('extract_images', False)
            )
            
            result = self.scraper.scrape_url(scrape_request)
            
            return {
                'success': result.success,
                'data': result.data,
                'error': result.error,
                'timestamp': result.timestamp,
                'url': result.url
            }
            
        except KeyError as e:
            return {
                'success': False,
                'error': f'Missing required field: {e}',
                'timestamp': time.time()
            }

    def handle_scrape_pubmed(self, request_data: Dict) -> Dict:
        """Handle PubMed scraping request"""
        try:
            scrape_request = PubMedScrapeRequest(
                query=request_data['query'],
                max_results=request_data.get('max_results', 10)
            )
            
            result = self.scraper.scrape_pubmed(scrape_request)
            
            return {
                'success': result.success,
                'data': result.data,
                'error': result.error,
                'timestamp': result.timestamp,
                'url': result.url
            }
            
        except KeyError as e:
            return {
                'success': False,
                'error': f'Missing required field: {e}',
                'timestamp': time.time()
            }
    
    def handle_scrape_multiple(self, request_data: Dict) -> Dict:
        """Handle multiple URL scraping using functional approach"""
        try:
            urls_data = request_data['urls']
            
            # Create scrape requests
            scrape_requests = [
                ScrapeRequest(
                    url=url_data['url'],
                    selectors=url_data.get('selectors'),
                    headers=url_data.get('headers'),
                    timeout=url_data.get('timeout', 30),
                    extract_links=url_data.get('extract_links', False),
                    extract_images=url_data.get('extract_images', False)
                )
                for url_data in urls_data
            ]
            
            # Scrape all URLs using map
            results = list(map(self.scraper.scrape_url, scrape_requests))
            
            # Convert results to dict format
            results_data = [
                {
                    'success': result.success,
                    'data': result.data,
                    'error': result.error,
                    'timestamp': result.timestamp,
                    'url': result.url
                }
                for result in results
            ]
            
            return {
                'success': True,
                'results': results_data,
                'total_processed': len(results),
                'timestamp': time.time()
            }
            
        except KeyError as e:
            return {
                'success': False,
                'error': f'Missing required field: {e}',
                'timestamp': time.time()
            }
    
    def handle_health_check(self, request_data: Dict) -> Dict:
        """Handle health check request"""
        return {
            'success': True,
            'status': 'healthy',
            'server_time': time.time(),
            'version': '1.0.0'
        }
    
    def start(self) -> None:
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.running = True
            
            logger.info(f"Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            server_socket.close()
            logger.info("Server stopped")
    
    def stop(self) -> None:
        """Stop the server"""
        self.running = False

def main():
    """Main function to start the server"""
    server = ScrapingServer(host='0.0.0.0', port=8888)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        server.stop()

if __name__ == "__main__":
    main()
EOF

# Make server executable
chmod +x server.py

# Create systemd service
echo "⚙️  Creating systemd service..."
sudo tee /etc/systemd/system/pi-scraping-server.service > /dev/null << EOF
[Unit]
Description=Raspberry Pi Web Scraping Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create startup script
echo "🚀 Creating startup script..."
cat > start_server.sh << 'EOF'
#!/bin/bash
cd /opt/pi-scraping-server
source venv/bin/activate
python server.py
EOF

chmod +x start_server.sh

# Create client script for easy access
echo "📱 Creating client script..."
cat > client.py << 'EOF'
#!/usr/bin/env python3
"""
Raspberry Pi Web Scraping Client
Terminal client for connecting to Raspberry Pi scraping servers
"""

import socket
import json
import time
import sys
import argparse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from functools import partial
import getpass

@dataclass
class ServerConfig:
    host: str
    port: int
    api_key: str

class ScrapingClient:
    """Client for connecting to Raspberry Pi scraping server"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.socket = None
    
    def connect(self) -> bool:
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            self.socket.connect((self.config.host, self.config.port))
            print(f"✓ Connected to {self.config.host}:{self.config.port}")
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def disconnect(self) -> None:
        """Disconnect from server"""
        if self.socket:
            self.socket.close()
            self.socket = None
            print("✓ Disconnected from server")
    
    def send_request(self, request_data: Dict) -> Optional[Dict]:
        """Send request to server and get response"""
        if not self.socket:
            print("✗ Not connected to server")
            return None
        
        try:
            # Add API key to request
            request_data['api_key'] = self.config.api_key
            
            # Send request
            message = json.dumps(request_data)
            self.socket.send(message.encode('utf-8'))
            
            # Receive response
            response_data = self.socket.recv(8192).decode('utf-8')
            return json.loads(response_data)
            
        except Exception as e:
            print(f"✗ Request failed: {e}")
            return None
    
    def health_check(self) -> bool:
        """Check server health"""
        request = {
            'type': 'health_check'
        }
        
        response = self.send_request(request)
        if response and response.get('success'):
            print("✓ Server is healthy")
            print(f"  Server time: {time.ctime(response.get('server_time', 0))}")
            print(f"  Version: {response.get('version', 'unknown')}")
            return True
        else:
            print("✗ Server health check failed")
            if response:
                print(f"  Error: {response.get('error', 'Unknown error')}")
            return False
    
    def scrape_url(self, url: str, selectors: Optional[Dict[str, str]] = None,
                   headers: Optional[Dict[str, str]] = None, timeout: int = 30,
                   extract_links: bool = False, extract_images: bool = False) -> Optional[Dict]:
        """Scrape a single URL"""
        request = {
            'type': 'scrape_url',
            'url': url,
            'timeout': timeout,
            'extract_links': extract_links,
            'extract_images': extract_images
        }
        
        if selectors:
            request['selectors'] = selectors
        if headers:
            request['headers'] = headers
        
        print(f"🔄 Scraping: {url}")
        response = self.send_request(request)
        
        if response and response.get('success'):
            print(f"✓ Successfully scraped {url}")
            return response
        else:
            print(f"✗ Failed to scrape {url}")
            if response:
                print(f"  Error: {response.get('error', 'Unknown error')}")
            return response

def print_scrape_result(result: Dict, detailed: bool = False) -> None:
    """Print scraping result in a formatted way"""
    if not result:
        return
    
    print("\n" + "="*60)
    print(f"URL: {result.get('url', 'Unknown')}")
    print(f"Success: {'✓' if result.get('success') else '✗'}")
    print(f"Timestamp: {time.ctime(result.get('timestamp', 0))}")
    
    if result.get('error'):
        print(f"Error: {result['error']}")
        return
    
    data = result.get('data', {})
    
    # Print title
    if data.get('title'):
        print(f"Title: {data['title']}")
    
    # Print meta description
    if data.get('meta_description'):
        print(f"Description: {data['meta_description']}")
    
    # Print selected data
    if data.get('selected_data') and detailed:
        print("\nSelected Data:")
        for selector_name, values in data['selected_data'].items():
            print(f"  {selector_name}: {len(values)} items")
            for i, value in enumerate(values[:3]):  # Show first 3 items
                print(f"    {i+1}. {value[:100]}...")
            if len(values) > 3:
                print(f"    ... and {len(values) - 3} more items")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Raspberry Pi Web Scraping Client')
    parser.add_argument('host', help='Server host/IP address')
    parser.add_argument('port', type=int, help='Server port')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--url', help='Single URL to scrape')
    parser.add_argument('--health', action='store_true', help='Just check health and exit')
    
    args = parser.parse_args()
    
    # Get API key
    api_key = args.api_key
    if not api_key:
        api_key = getpass.getpass("API Key: ")
    
    # Create config
    config = ServerConfig(
        host=args.host,
        port=args.port,
        api_key=api_key
    )
    
    # Create client
    client = ScrapingClient(config)
    
    # Connect to server
    if not client.connect():
        sys.exit(1)
    
    try:
        # Health check mode
        if args.health:
            success = client.health_check()
            sys.exit(0 if success else 1)
        
        # Single URL mode
        if args.url:
            result = client.scrape_url(url=args.url, extract_links=True)
            if result:
                print_scrape_result(result, detailed=True)
            sys.exit(0 if result and result.get('success') else 1)
        
        # Interactive mode
        print("Interactive mode not implemented in setup version")
        print("Use --url parameter to scrape a single URL")
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
EOF

chmod +x client.py

# Configure firewall
echo "🔥 Configuring firewall..."
sudo ufw allow 8888/tcp
sudo ufw allow ssh
echo "y" | sudo ufw enable

# Configure fail2ban for additional security
echo "🛡️  Configuring fail2ban..."
sudo tee /etc/fail2ban/jail.local > /dev/null << EOF
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Enable and start the service
echo "⚡ Enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable pi-scraping-server
sudo systemctl start pi-scraping-server

# Create usage instructions
echo "📋 Creating usage instructions..."
cat > README.md << 'EOF'
# Raspberry Pi Web Scraping Server

## Server Management

### Start/Stop/Status
```bash
sudo systemctl start pi-scraping-server    # Start
sudo systemctl stop pi-scraping-server     # Stop
sudo systemctl restart pi-scraping-server  # Restart
sudo systemctl status pi-scraping-server   # Check status
```

### View Logs
```bash
sudo journalctl -u pi-scraping-server -f   # Follow logs
sudo journalctl -u pi-scraping-server -n 50  # Last 50 lines
```

### Manual Start (for testing)
```bash
cd /opt/pi-scraping-server
./start_server.sh
```

## Client Usage

### Health Check
```bash
python3 client.py <PI_IP> 8888 --health --api-key YOUR_API_KEY
```

### Scrape a URL
```bash
python3 client.py <PI_IP> 8888 --url https://example.com --api-key YOUR_API_KEY
```

### From Remote Machine
```bash
# Install client dependencies
pip3 install requests

# Use client
python3 client.py 192.168.1.100 8888 --url https://example.com --api-key YOUR_API_KEY
```

## API Key
The default API key is shown in the server logs when it starts.
Check with: `sudo journalctl -u pi-scraping-server | grep "Default API Key"`

## Security Features
- API key authentication
- Rate limiting (60 requests/minute per IP)
- Firewall configured (UFW)
- Fail2ban protection
- No personal data access

## Port Configuration
Default port: 8888
To change: Edit /etc/systemd/system/pi-scraping-server.service

## Network Access
Make sure port 8888 is open on your router if accessing from outside your network.
Consider using VPN or SSH tunneling for remote access.
EOF

# Show completion message
echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "✓ Server installed at: $PROJECT_DIR"
echo "✓ Service enabled: pi-scraping-server"
echo "✓ Firewall configured (port 8888 open)"
echo "✓ Fail2ban enabled for SSH protection"
echo ""
echo "📋 Next Steps:"
echo "1. Get API key: sudo journalctl -u pi-scraping-server | grep 'Default API Key'"
echo "2. Test locally: cd $PROJECT_DIR && python3 client.py localhost 8888 --health"
echo "3. Check status: sudo systemctl status pi-scraping-server"
echo "4. View logs: sudo journalctl -u pi-scraping-server -f"
echo ""
echo "🔗 Server will be accessible at: $(hostname -I | awk '{print $1}'):8888"
echo "📖 Read README.md for detailed usage instructions"