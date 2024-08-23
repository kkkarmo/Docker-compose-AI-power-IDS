# AI Power IDS

AI Power IDS is a Dockerized application that processes log files, extracts public IPs, checks them against VirusTotal, and performs additional analysis using the Tavily API and LLAMA2 for advanced text processing. It is designed to help monitor and analyze network traffic for potential threats.

## Features

- Extracts public IPs from Suricata `eve.json` logs.
- Checks IPs against VirusTotal for malicious activity.
- Utilizes the Tavily API for further analysis of flagged IPs.
- Integrates LLAMA2 for advanced text generation and analysis.
- Runs scheduled tasks to process logs and IPs periodically.
- Supports Docker for easy deployment and management.

## Prerequisites

- Docker
- Docker Compose
- PostgreSQL (managed by Docker in this setup)

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-power-ids.git
cd ai-power-ids

Set Up Environment Variables
Create a .env file in the root of the project and define the following variables:
text
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_HOST=db
DB_PORT=5432
LOG_FILE_PATH=/path/to/suricata/eve.json
VT_RESULT_FILE_PATH=vt_results.txt
CHECKED_IPS_FILE=checked_ips.pkl
PUBLIC_IPS_FILE=Public_IPs.txt
TAVILY_API_KEY=your_tavily_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
LLAMA2_HOST=20.20.20.26  # Change to your LLAMA2 service address
USE_MOCK_RESPONSES=False

Build and Run the Application
Build the Docker image:
bash
docker-compose build

Start the application:
bash
docker-compose up -d

Check the logs:
bash
docker-compose logs -f

Usage
The application will automatically monitor the specified log file for changes and process new entries.
It will extract public IPs, check them against VirusTotal, and perform additional analysis using the Tavily API.
The LLAMA2 integration allows for advanced text generation based on log data, enhancing the analysis capabilities.
Results will be stored in a PostgreSQL database.
Stopping the Application
To stop the application, run:
bash
docker-compose down

Contributing
Contributions are welcome! Please submit a pull request or open an issue for any suggestions or improvements.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments
Suricata for network threat detection.
VirusTotal for malware analysis.
Tavily for additional threat intelligence.
LLAMA2 for advanced text processing and generation.
