# Web-Fuzzer

A Python-based web application fuzzing framework designed for security testing of e-commerce platforms. It identifies vulnerabilities by fuzzing directories, subdomains, API endpoints, URL parameters, and virtual hosts. Available as a Docker container for easy deployment and isolation.

## Features
- **Directory Fuzzing**: Discover hidden directories.
- **Subdomain Discovery**: Identify subdomains of the target domain.
- **API Endpoint Testing**: Test API security and parameter handling.
- **URL Parameter Fuzzing**: Probe vulnerabilities in query parameters.
- **Virtual Host Fuzzing**: Discover hidden virtual hosts.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/raulskat/Web-Fuzzer.git
   cd web-fuzzer
   ```

2. Install dependencies:
   ```bash
    pip install -r requirements.txt
   ```

3. Optional: Set up a virtual environment for Python (recommended for isolating dependencies):
   ```bash
     python -m venv venv
     source venv/bin/activate   # For Linux/Mac
     venv\Scripts\activate      # For Windows
   ```

## Docker Installation

### Prerequisites
- Docker installed on your system
- Minimum system requirements:
  - 2GB RAM
  - 2 CPU cores
  - 1GB free disk space

### Environment Variables
The following environment variables are required:
- `COHERE_API_KEY`: Your Cohere API key for advanced text processing
- `FLASK_ENV`: Set to 'production' for deployment (default in Docker)
- `FLASK_APP`: Application entry point (default: app.py)

### Running with Docker

1. Pull the Docker image:
   ```bash
   docker pull username/web-fuzzer:latest
   ```

2. Run the container:
   ```bash
   docker run -d \
     -p 5000:5000 \
     -e COHERE_API_KEY=your_api_key \
     -v $(pwd)/wordlists:/app/wordlists \
     -v $(pwd)/results:/app/results \
     -v $(pwd)/uploads:/app/uploads \
     -v $(pwd)/config:/app/config \
     username/web-fuzzer:latest
   ```

### Docker Volume Mounts
- `/app/wordlists`: Directory containing wordlists for fuzzing
- `/app/results`: Directory where scan results are stored
- `/app/uploads`: Directory for uploaded files
- `/app/config`: Directory containing configuration files

### Docker Tags
- `latest`: Most recent stable release
- `v1.0.0`: Specific version release
- `beta`: Development version (if available)

### Health Checks
The Docker container includes a health check that monitors the application's status every 30 seconds. The application is considered healthy if it responds to HTTP requests on port 5000.

## Usage Instructions

1. **Configure `default_config.json`:**
   - Navigate to the `config/` directory.
   - Open and modify the `default_config.json` file with your desired settings.
   - Example configuration:
      ```json
     {
       "base_url": "https://example.com",
       "wordlist": "path/to/wordlist.txt",
       "timeout": 10
     }
      ```

2. **Run the Desired Fuzzing Module:**
   Execute the following command to run the fuzzing module of your choice.

   - For **Directory Fuzzing**:
     ```bash
     python -m src.fuzzing.directories
     ```
   - For **SubDomain Fuzzing**:
     ```bash
     python -m src.fuzzing.subdomains 
     ```
   - For **API EndPoints Fuzzing**:
     ```bash
     python -m src.fuzzing.api_endpoints
     ```
   - For **testing** all:
     ```bash
     python -m tests.test_fuzzing
     ```

## Contributing
Feel free to fork the repository and submit pull requests.

## License
MIT License. See LICENSE for details.