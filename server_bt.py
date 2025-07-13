#!/usr/bin/env python3
"""
Bluetooth Raspberry Pi Web Scraping Server
Allows nearby devices to connect via Bluetooth for anonymous web scraping
"""

from pybluez2 import bluetooth
import threading
import json
import time
import secrets
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import requests
from bs4 import BeautifulSoup
import uuid
import subprocess
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RequestType(Enum):
    SCRAPE_URL = "scrape_url"
    SCRAPE_MULTIPLE = "scrape_multiple"
    HEALTH_CHECK = "health_check"
    DISCOVER = "discover"
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

class BluetoothSecurityManager:
    """Handles Bluetooth authentication and session management"""
    
    def __init__(self):
        self.active_sessions: Dict[str, Dict] = {}
        self.session_timeout = 3600  # 1 hour
        self.device_whitelist: set = set()
        self.max_sessions_per_device = 3
        self.request_history: Dict[str, List[float]] = {}
        self.max_requests_per_minute = 30  # Lower for Bluetooth
    
    def generate_session_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def create_session(self, device_address: str, device_name: str) -> Tuple[bool, str, Optional[str]]:
        """Create new session for device"""
        # Check if device has too many active sessions
        active_device_sessions = sum(
            1 for session in self.active_sessions.values()
            if session['device_address'] == device_address
        )
        
        if active_device_sessions >= self.max_sessions_per_device:
            return False, "Too many active sessions for this device", None
        
        session_token = self.generate_session_token()
        session_data = {
            'device_address': device_address,
            'device_name': device_name,
            'created_at': time.time(),
            'last_activity': time.time(),
            'request_count': 0
        }
        
        self.active_sessions[session_token] = session_data
        logger.info(f"Created session for {device_name} ({device_address})")
        
        return True, "Session created", session_token
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[Dict]]:
        """Validate session token"""
        if session_token not in self.active_sessions:
            return False, None
        
        session = self.active_sessions[session_token]
        current_time = time.time()
        
        # Check if session expired
        if current_time - session['created_at'] > self.session_timeout:
            del self.active_sessions[session_token]
            return False, None
        
        # Update last activity
        session['last_activity'] = current_time
        return True, session
    
    def check_rate_limit(self, device_address: str) -> bool:
        """Check if device has exceeded rate limit"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Filter requests from last minute
        recent_requests = list(filter(
            lambda timestamp: timestamp > minute_ago,
            self.request_history.get(device_address, [])
        ))
        
        # Update history
        self.request_history[device_address] = recent_requests
        
        return len(recent_requests) < self.max_requests_per_minute
    
    def log_request(self, device_address: str) -> None:
        """Log request timestamp"""
        if device_address not in self.request_history:
            self.request_history[device_address] = []
        self.request_history[device_address].append(time.time())
    
    def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions"""
        current_time = time.time()
        expired_tokens = [
            token for token, session in self.active_sessions.items()
            if current_time - session['created_at'] > self.session_timeout
        ]
        
        for token in expired_tokens:
            device_addr = self.active_sessions[token]['device_address']
            logger.info(f"Session expired for {device_addr}")
            del self.active_sessions[token]

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

class BluetoothScrapingServer:
    """Main Bluetooth server class"""
    
    def __init__(self, service_name: str = "Pi-Scraper", service_id: str = None):
        self.service_name = service_name
        self.service_id = service_id or str(uuid.uuid4())
        self.security_manager = BluetoothSecurityManager()
        self.scraper = WebScraper()
        self.running = False
        self.server_socket = None
        
        # Bluetooth service UUID (random UUID for our service)
        self.service_uuid = "12345678-1234-5678-9abc-123456789abc"
        
    def setup_bluetooth_service(self) -> bool:
        """Setup Bluetooth service advertisement"""
        try:
            # Make device discoverable
            subprocess.run(['sudo', 'hciconfig', 'hci0', 'piscan'], check=True)
            logger.info("Bluetooth device set to discoverable")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to make device discoverable: {e}")
            return False
    
    def handle_client(self, client_socket: bluetooth.BluetoothSocket, address: str) -> None:
        """Handle individual Bluetooth client connection"""
        logger.info(f"Bluetooth client connected: {address}")
        
        # Get device info
        try:
            device_name = bluetooth.lookup_name(address) or "Unknown Device"
        except:
            device_name = "Unknown Device"
        
        session_created = False
        session_token = None
        
        try:
            while True:
                # Receive data (Bluetooth has smaller buffer)
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                # Process request
                response = self.process_bluetooth_request(
                    data, address, device_name, session_token
                )
                
                # Check if session was created
                response_data = json.loads(response)
                if response_data.get('session_token'):
                    session_token = response_data['session_token']
                    session_created = True
                
                # Send response (split if too large for Bluetooth)
                self.send_large_message(client_socket, response)
                
        except Exception as e:
            logger.error(f"Error handling Bluetooth client {address}: {e}")
        finally:
            client_socket.close()
            logger.info(f"Bluetooth client disconnected: {address}")
    
    def send_large_message(self, socket: bluetooth.BluetoothSocket, message: str) -> None:
        """Send large message by splitting into chunks"""
        chunk_size = 1000  # Bluetooth safe chunk size
        
        if len(message) <= chunk_size:
            socket.send(message.encode('utf-8'))
        else:
            # Send multi-part message
            chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
            
            # Send header with chunk count
            header = json.dumps({
                "multi_part": True,
                "total_chunks": len(chunks)
            })
            socket.send(header.encode('utf-8'))
            
            # Wait for acknowledgment
            ack = socket.recv(10).decode('utf-8')
            if ack != "ACK":
                return
            
            # Send chunks
            for i, chunk in enumerate(chunks):
                chunk_msg = json.dumps({
                    "chunk_id": i,
                    "data": chunk
                })
                socket.send(chunk_msg.encode('utf-8'))
                
                # Wait for chunk acknowledgment
                ack = socket.recv(10).decode('utf-8')
                if ack != "ACK":
                    break
    
    def process_bluetooth_request(self, data: str, device_address: str, 
                                device_name: str, session_token: Optional[str]) -> str:
        """Process Bluetooth request"""
        try:
            request_data = json.loads(data)
            request_type = request_data.get('type')
            
            # Handle discovery request (no auth needed)
            if request_type == RequestType.DISCOVER.value:
                return json.dumps({
                    'success': True,
                    'service_name': self.service_name,
                    'service_id': self.service_id,
                    'capabilities': ['scrape_url', 'scrape_multiple', 'scrape_pubmed', 'health_check'],
                    'timestamp': time.time()
                })
            
            # Check session for other requests
            if not session_token:
                # Create new session
                success, message, token = self.security_manager.create_session(
                    device_address, device_name
                )
                if not success:
                    return json.dumps({
                        'success': False,
                        'error': message,
                        'timestamp': time.time()
                    })
                
                return json.dumps({
                    'success': True,
                    'session_token': token,
                    'message': 'Session created. Resend your request with this token.',
                    'timestamp': time.time()
                })
            
            # Validate session
            valid, session_data = self.security_manager.validate_session(session_token)
            if not valid:
                return json.dumps({
                    'success': False,
                    'error': 'Invalid or expired session',
                    'timestamp': time.time()
                })
            
            # Check rate limit
            if not self.security_manager.check_rate_limit(device_address):
                return json.dumps({
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'timestamp': time.time()
                })
            
            # Log request
            self.security_manager.log_request(device_address)
            
            # Route request
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
        """Handle multiple URL scraping"""
        try:
            urls_data = request_data['urls']
            
            # Limit for Bluetooth (smaller bandwidth)
            if len(urls_data) > 5:
                return {
                    'success': False,
                    'error': 'Maximum 5 URLs allowed for Bluetooth connections',
                    'timestamp': time.time()
                }
            
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
            
            # Scrape all URLs
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
            'version': '1.0.0-bluetooth',
            'active_sessions': len(self.security_manager.active_sessions)
        }
    
    def start(self) -> None:
        """Start the Bluetooth server"""
        if not self.setup_bluetooth_service():
            logger.error("Failed to setup Bluetooth service")
            return
        
        try:
            # Create server socket
            self.server_socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self.server_socket.bind(("", bluetooth.PORT_ANY))
            self.server_socket.listen(5)
            
            port = self.server_socket.getsockname()[1]
            
            # Advertise service
            bluetooth.advertise_service(
                self.server_socket,
                self.service_name,
                service_id=self.service_uuid,
                service_classes=[bluetooth.SERIAL_PORT_CLASS],
                profiles=[bluetooth.SERIAL_PORT_PROFILE]
            )
            
            self.running = True
            logger.info(f"Bluetooth server started on port {port}")
            logger.info(f"Service UUID: {self.service_uuid}")
            
            # Start session cleanup thread
            cleanup_thread = threading.Thread(target=self.session_cleanup_loop)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address[0])
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting Bluetooth connection: {e}")
                        
        except Exception as e:
            logger.error(f"Bluetooth server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            logger.info("Bluetooth server stopped")
    
    def session_cleanup_loop(self) -> None:
        """Periodic session cleanup"""
        while self.running:
            time.sleep(300)  # Every 5 minutes
            self.security_manager.cleanup_expired_sessions()
    
    def stop(self) -> None:
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

def main():
    """Main function to start the Bluetooth server"""
    server = BluetoothScrapingServer(service_name="Pi-Scraper-BT")
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        server.stop()

if __name__ == "__main__":
    main()