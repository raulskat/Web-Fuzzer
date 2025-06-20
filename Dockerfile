FROM python:3.9-slim

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file separately to leverage Docker caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Create necessary directories
RUN mkdir -p uploads results wordlists config

# Add default wordlists if they don't exist
RUN test -f wordlists/directory_wordlist.txt || echo -e "admin\nlogin\nwp-admin\nadministrator\nphpmyadmin\nbackup\nconfig\n.git\n.env\napi\ntest\ndev" > wordlists/directory_wordlist.txt
RUN test -f wordlists/subdomain_wordlist.txt || echo -e "www\nmail\nftp\nwebmail\nlogin\nadmin\nblog\ndev\ntest\nstaging" > wordlists/subdomain_wordlist.txt
RUN test -f wordlists/api_endpoints.txt || echo -e "api\napi/v1\napi/v2\nrest\ngraphql\nquery\nendpoint\nservice\nauth\nlogin" > wordlists/api_endpoints.txt

# Create empty .env file to prevent dotenv loading errors
RUN touch .env

# Expose the Flask port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Healthcheck to verify the service is running properly
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 CMD curl -f http://localhost:5000/ || exit 1

# Run the application
# Run the application with Gunicorn
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]
