# Web-Fuzzer

A Python-based web application fuzzing framework designed for security testing of e-commerce platforms. It identifies vulnerabilities by fuzzing directories, subdomains, API endpoints, URL parameters, and virtual hosts.

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