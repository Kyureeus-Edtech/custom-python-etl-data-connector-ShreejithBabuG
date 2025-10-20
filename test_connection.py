"""
Test Script for CERT Threat Intelligence ETL
Tests connectivity to APIs and MongoDB before running full ETL
"""

import os
import sys
import requests
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
ENDC = '\033[0m'
BOLD = '\033[1m'


def print_header(text):
    """Print formatted header"""
    print(f"\n{BOLD}{BLUE}{'='*60}{ENDC}")
    print(f"{BOLD}{BLUE}{text:^60}{ENDC}")
    print(f"{BOLD}{BLUE}{'='*60}{ENDC}\n")


def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓ {text}{ENDC}")


def print_error(text):
    """Print error message"""
    print(f"{RED}✗ {text}{ENDC}")


def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠ {text}{ENDC}")


def print_info(text):
    """Print info message"""
    print(f"  {text}")


def test_environment():
    """Test if environment variables are loaded"""
    print_header("Testing Environment Configuration")
    
    load_dotenv()
    
    # Check .env file exists
    if not os.path.exists('.env'):
        print_error(".env file not found")
        print_info("Create .env file by copying .env.template:")
        print_info("  cp .env.template .env")
        return False
    
    print_success(".env file found")
    
    # Check required variables
    mongo_uri = os.getenv('MONGODB_URI')
    mongo_db = os.getenv('MONGODB_DATABASE')
    otx_key = os.getenv('OTX_API_KEY')
    
    if mongo_uri:
        print_success(f"MONGODB_URI is set: {mongo_uri[:30]}...")
    else:
        print_error("MONGODB_URI is not set")
        return False
    
    if mongo_db:
        print_success(f"MONGODB_DATABASE is set: {mongo_db}")
    else:
        print_warning("MONGODB_DATABASE is not set (will use default)")
    
    if otx_key:
        print_success(f"OTX_API_KEY is set: {otx_key[:10]}...")
    else:
        print_warning("OTX_API_KEY is not set (optional, but recommended)")
    
    return True


def test_mongodb():
    """Test MongoDB connectivity"""
    print_header("Testing MongoDB Connection")
    
    load_dotenv()
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    db_name = os.getenv('MONGODB_DATABASE', 'threat_intelligence')
    
    try:
        print_info(f"Connecting to: {mongo_uri[:50]}...")
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        
        # Test connection
        client.server_info()
        print_success("MongoDB connection successful")
        
        # Get database
        db = client[db_name]
        print_success(f"Database '{db_name}' accessible")
        
        # List collections
        collections = db.list_collection_names()
        if collections:
            print_success(f"Found {len(collections)} existing collections:")
            for col in collections:
                count = db[col].count_documents({})
                print_info(f"  - {col}: {count} documents")
        else:
            print_info("No collections yet (will be created when ETL runs)")
        
        client.close()
        return True
        
    except Exception as e:
        print_error(f"MongoDB connection failed: {str(e)}")
        print_info("\nTroubleshooting:")
        print_info("1. Ensure MongoDB is running: mongod --version")
        print_info("2. Check connection string in .env file")
        print_info("3. For local: mongodb://localhost:27017/")
        print_info("4. For Atlas: mongodb+srv://user:pass@cluster.mongodb.net/")
        return False


def test_urlhaus_api():
    """Test URLhaus API connectivity"""
    print_header("Testing URLhaus API")
    
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    
    try:
        print_info(f"Sending request to: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('query_status') == 'ok':
            urls = data.get('urls', [])
            print_success(f"URLhaus API working ({len(urls)} URLs available)")
            
            if urls:
                sample = urls[0]
                print_info(f"Sample data:")
                print_info(f"  - URL: {sample.get('url', 'N/A')[:50]}...")
                print_info(f"  - Threat: {sample.get('threat', 'N/A')}")
                print_info(f"  - Status: {sample.get('url_status', 'N/A')}")
            
            return True
        else:
            print_error(f"API returned status: {data.get('query_status')}")
            return False
            
    except requests.exceptions.Timeout:
        print_error("Request timeout - API might be slow")
        return False
    except requests.exceptions.ConnectionError:
        print_error("Connection error - check internet connection")
        return False
    except Exception as e:
        print_error(f"URLhaus API test failed: {str(e)}")
        return False


def test_feodo_api():
    """Test Feodo Tracker API connectivity"""
    print_header("Testing Feodo Tracker API")
    
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    
    try:
        print_info(f"Sending request to: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if isinstance(data, list) and len(data) > 0:
            print_success(f"Feodo Tracker API working ({len(data)} C2 servers)")
            
            sample = data[0]
            print_info(f"Sample data:")
            print_info(f"  - IP: {sample.get('ip_address', 'N/A')}")
            print_info(f"  - Malware: {sample.get('malware', 'N/A')}")
            print_info(f"  - Status: {sample.get('status', 'N/A')}")
            
            return True
        else:
            print_warning("API returned empty data")
            return False
            
    except Exception as e:
        print_error(f"Feodo Tracker API test failed: {str(e)}")
        return False


def test_otx_api():
    """Test AlienVault OTX API connectivity"""
    print_header("Testing AlienVault OTX API")
    
    load_dotenv()
    otx_key = os.getenv('OTX_API_KEY', '')
    
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5"
    headers = {}
    
    if otx_key:
        headers['X-OTX-API-KEY'] = otx_key
        print_info("Using API key for authentication")
    else:
        print_warning("No API key found - testing without authentication")
    
    try:
        print_info(f"Sending request to: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        results = data.get('results', [])
        
        if results:
            print_success(f"AlienVault OTX API working ({len(results)} pulses)")
            
            sample = results[0]
            print_info(f"Sample data:")
            print_info(f"  - Name: {sample.get('name', 'N/A')[:50]}...")
            print_info(f"  - Author: {sample.get('author_name', 'N/A')}")
            print_info(f"  - IOCs: {sample.get('indicator_count', 0)}")
            
            return True
        else:
            print_warning("API returned no pulses")
            print_info("Consider adding an OTX API key in .env file")
            print_info("Get key from: https://otx.alienvault.com/api")
            return False
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            print_error("Authentication failed - check OTX_API_KEY")
            print_info("Get API key from: https://otx.alienvault.com/api")
        else:
            print_error(f"HTTP error {e.response.status_code}")
        return False
    except Exception as e:
        print_error(f"AlienVault OTX API test failed: {str(e)}")
        return False


def test_dependencies():
    """Test if all required Python packages are installed"""
    print_header("Testing Python Dependencies")
    
    required = [
        ('requests', 'HTTP library'),
        ('pymongo', 'MongoDB driver'),
        ('dotenv', 'Environment variables'),
    ]
    
    all_installed = True
    
    for package, description in required:
        try:
            __import__(package)
            print_success(f"{package:15} - {description}")
        except ImportError:
            print_error(f"{package:15} - NOT INSTALLED")
            all_installed = False
    
    if not all_installed:
        print_info("\nInstall missing packages:")
        print_info("  pip install -r requirements.txt")
    
    return all_installed


def main():
    """Run all tests"""
    print(f"\n{BOLD}CERT Threat Intelligence ETL - Connection Tester{ENDC}")
    print(f"Testing environment setup and API connectivity...")
    print(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    
    results = {
        'Dependencies': test_dependencies(),
        'Environment': test_environment(),
        'MongoDB': test_mongodb(),
        'URLhaus API': test_urlhaus_api(),
        'Feodo Tracker API': test_feodo_api(),
        'AlienVault OTX API': test_otx_api(),
    }
    
    # Summary
    print_header("Test Summary")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = f"{GREEN}PASS{ENDC}" if result else f"{RED}FAIL{ENDC}"
        print(f"  {test_name:20} [{status}]")
    
    print(f"\n{BOLD}Results: {passed}/{total} tests passed{ENDC}")
    
    if passed == total:
        print(f"\n{GREEN}{BOLD}✓ All tests passed! Ready to run ETL pipeline.{ENDC}")
        print(f"{GREEN}  Run: python etl_connector.py{ENDC}\n")
        return 0
    else:
        print(f"\n{RED}{BOLD}✗ Some tests failed. Fix issues before running ETL.{ENDC}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())