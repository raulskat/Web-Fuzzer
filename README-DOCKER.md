# Web-Fuzzer Docker Setup

This document provides instructions for running the Web-Fuzzer application using Docker.

## Prerequisites

- Docker
- Docker Compose (optional, but recommended)

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/Web-Fuzzer.git
   cd Web-Fuzzer
   ```

2. (Optional) Configure the Cohere API key in the `docker-compose.yml` file if you want to use AI-generated wordlists:
   ```yaml
   environment:
     - COHERE_API_KEY=your_api_key_here
   ```

3. Build and start the application:
   ```
   docker-compose up -d
   ```

4. Access the application at [http://localhost:5000](http://localhost:5000)

5. To stop the application:
   ```
   docker-compose down
   ```

### Using Docker Directly

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/Web-Fuzzer.git
   cd Web-Fuzzer
   ```

2. Build the Docker image:
   ```
   docker build -t web-fuzzer .
   ```

3. Run the container:
   ```
   docker run -p 5000:5000 -v $(pwd)/results:/app/results -v $(pwd)/wordlists:/app/wordlists -v $(pwd)/uploads:/app/uploads -v $(pwd)/config:/app/config web-fuzzer
   ```

4. Access the application at [http://localhost:5000](http://localhost:5000)

## Persistent Data

The following directories are mounted as volumes to preserve data between container restarts:

- `./results`: Contains the results of fuzzing operations
- `./wordlists`: Contains the wordlists used for fuzzing
- `./uploads`: Contains user-uploaded files
- `./config`: Contains application configuration

## Features

The Web-Fuzzer in Docker provides the following features:

- Directory Fuzzing
- Subdomain Fuzzing
- API Endpoints Fuzzing
- Parameter Fuzzing
- Virtual Host Fuzzing
- Results Dashboard

## Troubleshooting

1. **Port conflicts**: If port 5000 is already in use, change the port mapping in the `docker-compose.yml` file or the `docker run` command.

2. **Permission issues**: Make sure the directories for volumes exist and have appropriate permissions.

3. **Missing wordlists**: Default wordlists are created automatically. If you need custom wordlists, place them in the `wordlists` directory before starting the container. 