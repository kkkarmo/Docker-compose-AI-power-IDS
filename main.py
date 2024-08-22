import os
import json
import psycopg2
from psycopg2 import pool, sql
import requests
from datetime import datetime, timedelta
from time import sleep
from concurrent.futures import ThreadPoolExecutor
import schedule
import logging
import re
from dotenv import load_dotenv
from ratelimit import limits, sleep_and_retry
import pickle
import traceback
import ipaddress

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename='debug.log', filemode='w',
                    format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

# PostgreSQL database connection pool
DATABASE_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}
connection_pool = psycopg2.pool.SimpleConnectionPool(1, 10, **DATABASE_CONFIG)

# File paths
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', '/app/logs/eve.json')
VT_RESULT_FILE_PATH = os.getenv('VT_RESULT_FILE_PATH', '/app/data/vt_results.txt')
CHECKED_IPS_FILE = os.getenv('CHECKED_IPS_FILE', '/app/data/checked_ips.pkl')
PUBLIC_IPS_FILE = os.getenv('PUBLIC_IPS_FILE', '/app/data/Public_IPs.txt')

# API keys from environment variables
TAVILY_API_KEY = os.getenv('TAVILY_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
USE_MOCK_RESPONSES = os.getenv('USE_MOCK_RESPONSES', 'False').lower() in ('true', '1', 't')

CHECK_INTERVAL = timedelta(hours=24)  # Recheck IPs every 24 hours

class EveFileHandler:
    @staticmethod
    def extract_public_ips(file_path):
        logging.debug(f"Extracting public IPs from file: {file_path}")
        try:
            with open(file_path, 'r') as f:
                public_ips = set()
                for line in f:
                    try:
                        log_entry = json.loads(line)
                        ip = log_entry.get('src_ip')
                        if ip and EveFileHandler.is_public_ip(ip):
                            public_ips.add(ip)
                    except json.JSONDecodeError:
                        logging.error(f"Error decoding JSON from line: {line}")
            with open(PUBLIC_IPS_FILE, 'w') as f:
                for ip in public_ips:
                    f.write(f"{ip}\n")
            logging.debug(f"Public IPs extracted and written to {PUBLIC_IPS_FILE}")
        except Exception as e:
            logging.error(f"Error processing file: {str(e)}")
            traceback.print_exc()

    @staticmethod
    def is_public_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

class IPFileHandler:
    def __init__(self, api_key):
        self.api_key = api_key
        self.vt_url = 'https://www.virustotal.com/api/v3/ip_addresses/'
        self.checked_ips = self.load_checked_ips()
        logging.debug(f"Initialized with API key: {api_key[:5]}...{api_key[-5:]}")

    def process_ip_file(self, file_path):
        logging.debug(f"Processing file: {file_path}")
        try:
            with open(file_path, 'r') as f:
                ips = f.read().splitlines()
                logging.debug(f"IPs found: {ips}")
                for ip in ips:
                    if self.should_check_ip(ip):
                        result = self.check_ip(ip)
                        self.write_result(result)
                        logging.debug(result)  # Log result
                        self.checked_ips[ip] = datetime.now()
                        self.save_checked_ips()
                        sleep(15)  # Wait 15 seconds between checks
                    else:
                        logging.debug(f"Skipping IP (recently checked): {ip}")
        except Exception as e:
            logging.error(f"Error processing file: {str(e)}")
            traceback.print_exc()

    def should_check_ip(self, ip):
        last_checked = self.checked_ips.get(ip)
        if last_checked is None:
            return True
        return datetime.now() - last_checked > CHECK_INTERVAL

    @sleep_and_retry
    @limits(calls=4, period=60)  # 4 calls per minute
    def check_ip(self, ip):
        logging.debug(f"Checking IP: {ip}")
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        try:
            response = requests.get(f"{self.vt_url}{ip}", headers=headers)
            logging.debug(f"Response status code: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return f"IP: {ip}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"
            elif response.status_code == 429:
                logging.debug(f"Rate limit exceeded for IP: {ip}. Waiting before retry...")
                sleep(60)  # Wait for 60 seconds before retrying
                return self.check_ip(ip)  # Retry the request
            else:
                return f"IP: {ip}, Error: Unable to fetch results, status code: {response.status_code}"
        except Exception as e:
            logging.error(f"Error checking IP {ip}: {str(e)}")
            traceback.print_exc()
            return f"IP: {ip}, Error: {str(e)}"

    def write_result(self, result):
        logging.debug(f"Writing result: {result}")
        try:
            with open(VT_RESULT_FILE_PATH, 'a') as f:
                f.write(f"{result}\n")
            logging.debug("Result written successfully")
        except Exception as e:
            logging.error(f"Error writing result: {str(e)}")
            traceback.print_exc()

    def load_checked_ips(self):
        try:
            with open(CHECKED_IPS_FILE, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            return {}

    def save_checked_ips(self):
        with open(CHECKED_IPS_FILE, 'wb') as f:
            pickle.dump(self.checked_ips, f)

def initialize_database():
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_analysis (
            id SERIAL PRIMARY KEY,
            log_entry TEXT,
            vt_result TEXT,
            analysis_result TEXT
        );
        CREATE TABLE IF NOT EXISTS results (
            ip TEXT PRIMARY KEY,
            result JSONB
        );
    ''')
    conn.commit()
    cursor.close()
    connection_pool.putconn(conn)

def process_log_data(combined_data_str):
    prompt = f"""Analyze the following log entry, VirusTotal result, and Tavily search results:

{combined_data_str}

Provide a concise summary of the security implications and any recommended actions."""

    response = requests.post(
        'http://localhost:11434/generate',
        json={'model': 'llama2', 'prompt': prompt}
    )
    if response.status_code == 200:
        return response.json().get('text', '')
    else:
        return "Error: Failed to process log data"

def save_to_database(log_entry, vt_result, analysis_result):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO log_analysis (log_entry, vt_result, analysis_result)
        VALUES (%s, %s, %s)
    ''', (log_entry, vt_result, analysis_result))
    conn.commit()
    cursor.close()
    connection_pool.putconn(conn)

def read_vt_results(file_path):
    logging.info(f"Attempting to read file: {file_path}")
    flagged_ips = []
    error_ips = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                logging.info(f"Processing line: {line.strip()}")
                match = re.match(r"IP: (\d+\.\d+\.\d+\.\d+), (?:Malicious: (\d+), Suspicious: (\d+)|Error: (.+))", line)
                if match:
                    ip, malicious, suspicious, error = match.groups()
                    if error:
                        error_ips.append((ip, error))
                    elif int(malicious) > 0 or int(suspicious) > 0:
                        flagged_ips.append((ip, int(malicious), int(suspicious)))
    except FileNotFoundError:
        logging.error(f"File {file_path} not found.")
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from file {file_path}.")
    logging.info(f"Flagged IPs: {flagged_ips}")
    logging.info(f"Error IPs: {error_ips}")
    return flagged_ips, error_ips

def mock_tavily_search(query):
    # Simulate API response
    mock_response = {
        "answer": f"This is a mock answer for the query: {query}",
        "results": [
            {"title": "Mock Result 1", "content": "This is the content of mock result 1..."},
            {"title": "Mock Result 2", "content": "This is the content of mock result 2..."},
            {"title": "Mock Result 3", "content": "This is the content of mock result 3..."}
        ]
    }
    return mock_response

def tavily_search(query):
    if USE_MOCK_RESPONSES:
        return mock_tavily_search(query)
    url = "https://api.tavily.com/search"
    headers = {"content-type": "application/json"}
    payload = {
        "api_key": TAVILY_API_KEY,
        "query": query,
        "search_depth": "advanced",
        "include_answer": True
    }
    try:
        logging.info(f"Sending request to Tavily API for query: {query}")
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        logging.info(f"API Response Status Code: {response.status_code}")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"API Request Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logging.error(f"Error response: {e.response.text}")
        return {}

def save_tavily_results_to_database(data):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    for ip, result in data.items():
        cursor.execute(sql.SQL("""
            INSERT INTO results (ip, result)
            VALUES (%s, %s)
            ON CONFLICT (ip) DO UPDATE SET result = EXCLUDED.result
        """), (ip, json.dumps(result)))
    conn.commit()
    cursor.close()
    connection_pool.putconn(conn)

def get_tavily_result(ip):
    queries = [
        f"Why is IP {ip} flagged as malicious or suspicious?",
        f"What can be found about IP {ip} in terms of cybersecurity aspects?"
    ]
    results = []
    for query in queries:
        result = tavily_search(query)
        results.append(result)
    return results

def process_logs():
    vt_results, _ = read_vt_results(VT_RESULT_FILE_PATH)
    with open(LOG_FILE_PATH, 'r') as file:
        log_entries = [json.loads(line.strip()) for line in file]
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        for log_data in log_entries:
            ip = log_data.get('src_ip')
            if ip and EveFileHandler.is_public_ip(ip):
                vt_result = next((result for result in vt_results if result[0] == ip), None)
                
                if vt_result:
                    ip, malicious, suspicious = vt_result
                    vt_info = f"Malicious: {malicious}, Suspicious: {suspicious}"
                    tavily_results = get_tavily_result(ip)
                else:
                    vt_info = "No VT result"
                    tavily_results = []
                
                combined_data = {
                    "log": log_data,
                    "vt_result": vt_info,
                    "tavily_results": tavily_results
                }
                
                combined_data_str = json.dumps(combined_data)
                analysis_result = executor.submit(process_log_data, combined_data_str)
                save_to_database(json.dumps(log_data), vt_info, analysis_result.result())
            else:
                logging.debug(f"Skipping non-public IP: {ip}")

def process_ips():
    flagged_ips, error_ips = read_vt_results(VT_RESULT_FILE_PATH)
    if not flagged_ips and not error_ips:
        logging.info("No flagged or error IPs found.")
        return
    tavily_results = {}
    for ip, malicious, suspicious in flagged_ips:
        logging.info(f"Searching for information about IP: {ip} (Malicious: {malicious}, Suspicious: {suspicious})")
        queries = [
            f"Why is IP {ip} flagged as malicious or suspicious?",
            f"What can be found about IP {ip} in terms of cybersecurity aspects?"
        ]
        for query in queries:
            result = tavily_search(query)
            tavily_results[ip] = result
        if not USE_MOCK_RESPONSES:
            sleep(5)  # Add a 5-second delay between IP searches
    save_tavily_results_to_database(tavily_results)

def daily_processing():
    logging.info("Starting daily log processing")
    process_logs()
    process_ips()
    logging.info("Daily log processing completed")

if __name__ == '__main__':
    initialize_database()
    schedule.every().day.at("02:00").do(daily_processing)
    
    while True:
        schedule.run_pending()
        sleep(60)