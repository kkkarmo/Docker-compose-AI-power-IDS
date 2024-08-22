# Suricata IDS Log Analyzer

This Python application is designed to monitor and analyze logs from a Suricata Intrusion Detection System (IDS). It extracts public IP addresses from the logs, checks them against the VirusTotal API, and performs additional searches using the Tavily API. The results are stored in a PostgreSQL database for further analysis.

## Features

- Monitors Suricata log files for changes.
- Extracts public IP addresses from log entries.
- Checks IP addresses against the VirusTotal API for threat analysis.
- Gathers additional intelligence on flagged IPs using the Tavily API.
- Processes log entries and stores results in a PostgreSQL database.
- Scheduled tasks to run daily at 2 AM for log processing and IP checks.
- Configurable via environment variables.

## Requirements

- Python 3.9 or later
- PostgreSQL
- Docker and Docker Compose (for containerized deployment)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/kkkarmo/Docker-compose-AI-power-IDS.git
   cd suricata-ids-log-analyzer

2. **Set up a virtual environment (optional but recommended):**


  python -m venv venv
  source venv/bin/activate  
  On Windows use `venv\Scripts\activate`

3. **Install dependencies:**

 
  pip install -r requirements.txt

4. **Set up environment variables:**

Create a .env file in the root directory of the project:

DB_NAME=your_database_name

DB_USER=your_database_user

DB_PASSWORD=your_database_password

DB_HOST=localhost

DB_PORT=5432

TAVILY_API_KEY=your_tavily_api_key

VIRUSTOTAL_API_KEY=your_virustotal_api_key

USE_MOCK_RESPONSES=False

5. **Run the application using Docker Compose:**

Ensure Docker and Docker Compose are installed, then run:

docker-compose up --build

**Usage**

The application will monitor the specified Suricata log file (eve.json) for new entries.
It will extract public IP addresses and check them against VirusTotal and Tavily APIs.
Results will be stored in the PostgreSQL database.

**Directory Structure**

.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env
├── main.py  # The main application script
└── logs/    # Directory for log files
└── data/    # Directory for storing results and checked IPs

**Logging**

Logs are stored in debug.log in the root directory. You can adjust the logging level and format in the script.

**Contributing**
Feel free to submit issues or pull requests. Contributions are welcome!

**License**
This project is licensed under the MIT License. See the LICENSE file for more details.
