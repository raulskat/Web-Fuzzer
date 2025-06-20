#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime as dt, timedelta
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, make_response, jsonify
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import os
import json
import csv
from io import StringIO
import requests
import asyncio
import aiohttp
import shutil
import uuid
import secrets
import logging
from logging.handlers import RotatingFileHandler
from src.fuzzing.directories import DirectoryFuzzer
from src.fuzzing.subdomains import SubdomainFuzzer
from src.fuzzing.api_endpoints import ApiFuzzer
from src.utils.request_handler import RequestHandler
from src.fuzzing.parameters import ParameterFuzzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

# Create the Flask application
app = Flask(__name__)

# Production configurations
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    UPLOAD_FOLDER='uploads',
    RESULT_FOLDER='results',
    CONFIG_FILE='config/current_config.json',
    DEFAULT_CONFIG_FILE='config/default_config.json',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max file size
)

# Configure logging to file
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/web_fuzzer.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Web Fuzzer startup')

# Global variable to track fuzzing progress
fuzzing_tasks = {}

# Helper classes for progress tracking
class FuzzingProgress:
    def __init__(self, task_id, task_type, total=100):
        self.task_id = task_id
        self.task_type = task_type  # "directory", "subdomain", "api", "parameter", "virtualhost"
        self.total = total
        self.completed = 0
        self.status = "running"  # "running", "completed", "error"
        self.message = "Initializing..."
        self.results = None
        self.start_time = dt.now()
    
    def update(self, completed, message=None):
        self.completed = completed
        if message:
            self.message = message
    
    def complete(self, results=None):
        self.completed = self.total
        self.status = "completed"
        self.message = "Fuzzing completed"
        self.results = results
        
    def error(self, message):
        self.status = "error"
        self.message = message
    
    def to_dict(self):
        elapsed = (dt.now() - self.start_time).total_seconds()
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "progress": int((self.completed / self.total) * 100) if self.total > 0 else 0,
            "status": self.status,
            "message": self.message,
            "elapsed": elapsed
        }

# Create directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)
os.makedirs('config', exist_ok=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}

def load_config():
    """Load configuration from file or create from default if it doesn't exist"""
    if not os.path.exists(app.config['CONFIG_FILE']):
        # If config doesn't exist, copy the default
        if os.path.exists(app.config['DEFAULT_CONFIG_FILE']):
            shutil.copy(app.config['DEFAULT_CONFIG_FILE'], app.config['CONFIG_FILE'])
        else:
            # Create a basic default config if even the default doesn't exist
            default_config = {
                "target_url": "https://demo.owasp-juice.shop",
                "target_domain": "github.com",
                "directories": {
                    "enabled": True,
                    "wordlist": "wordlists/directory_wordlist.txt"
                },
                "subdomains": {
                    "enabled": True,
                    "wordlist": "wordlists/subdomain_wordlist.txt"
                },
                "api_endpoints": {
                    "enabled": True,
                    "wordlist": "wordlists/api_endpoints.txt"
                },
                "parameter_fuzzing": {
                    "enabled": True,
                    "wordlist": "wordlists/parameter_wordlist.txt"
                },
                "request_options": {
                    "method": "GET",
                    "timeout": 10,
                    "retries": 3
                },
                "rate_limiting": {
                    "enabled": True,
                    "requests_per_second": 5
                },
                "logging": {
                    "enabled": True,
                    "log_file": "fuzzer_log.log"
                }
            }
            with open(app.config['CONFIG_FILE'], 'w') as f:
                json.dump(default_config, f, indent=4)
    
    # Load and return the config
    try:
        with open(app.config['CONFIG_FILE'], 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        app.logger.error(f"Error loading config: {str(e)}")
        # Return a basic config in case of error
        return {
            "target_url": "https://example.com",
            "target_domain": "example.com",
            "directories": {"enabled": True},
            "subdomains": {"enabled": True},
            "api_endpoints": {"enabled": True},
            "parameter_fuzzing": {"enabled": True},
            "request_options": {"method": "GET", "timeout": 10, "retries": 3},
            "rate_limiting": {"enabled": True, "requests_per_second": 5},
            "logging": {"enabled": True, "log_file": "fuzzer_log.log"}
        }

def save_config(config_data):
    """Save configuration to file"""
    try:
        with open(app.config['CONFIG_FILE'], 'w') as f:
            json.dump(config_data, f, indent=4)
        return True
    except Exception as e:
        app.logger.error(f"Error saving config: {str(e)}")
        return False

# Load initial configuration
app_config = load_config()

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/directory_fuzzing', methods=['GET', 'POST'])
def directory_fuzzing():
    """Directory fuzzing page and functionality."""
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        use_wordlist = request.form.get('use_wordlist') == 'on'
        use_ai = request.form.get('use_ai') == 'on'
        wordlist_file = request.files.get('wordlist_file')
        verify_ssl = request.form.get('verify_ssl') == 'on'

        # Validate URL
        if not target_url:
            flash('Please enter a target URL', 'error')
            return redirect(url_for('directory_fuzzing'))

        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"
            
        # Generate a unique task ID
        task_id = str(uuid.uuid4())
        
        # Determine wordlist source
        if use_ai:
            wordlist_source = "ai"
            flash(f"Using AI to generate a targeted wordlist for {target_url}...", "info")
        elif use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            wordlist_source = "custom"
        else:
            wordlist_source = "predefined"
        
        # Process wordlist
        custom_wordlist_path = None
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            custom_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(custom_wordlist_path)
            
        # Create and store progress tracker
        progress = FuzzingProgress(task_id, "directory")
        fuzzing_tasks[task_id] = progress
        
        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"directories_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)
        
        # Start fuzzing in a background thread
        import threading
        def run_fuzzing():
            try:
                # Initialize directory fuzzer
                fuzzer = DirectoryFuzzer(
                    target_url=target_url,
                    wordlist_source=wordlist_source,
                    custom_wordlist_path=custom_wordlist_path,
                    verify_ssl=verify_ssl
                )
                
                # Set the progress callback
                fuzzer.set_progress_callback(lambda completed, total, message: 
                    progress.update(completed, message))
                
                # Run the fuzzing
                processed_urls = fuzzer.fuzz_directories()
                
                # Calculate statistics
                total_urls = len(processed_urls)
                def get_status(result):
                    """Helper to get status from either status or status_code"""
                    if isinstance(result.get('status_code'), int):
                        return result.get('status_code')
                    return result.get('status', 0)
                    
                status_2xx = sum(1 for r in processed_urls if 200 <= get_status(r) < 300)
                status_3xx = sum(1 for r in processed_urls if 300 <= get_status(r) < 400)
                status_4xx = sum(1 for r in processed_urls if 400 <= get_status(r) < 500)
                status_5xx = sum(1 for r in processed_urls if 500 <= get_status(r) < 600)
                
                # Prepare results structure
                results = {
                    "directories": processed_urls,
                    "subdomains": [],
                    "api_endpoints": [],
                    "meta": {
                        "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "tool": "Web Application Fuzzer",
                        "target_url": target_url,
                        "total_urls": total_urls,
                        "ssl_verification": verify_ssl,
                        "wordlist_source": wordlist_source,
                        "status_summary": {
                            "2xx": status_2xx,
                            "3xx": status_3xx,
                            "4xx": status_4xx,
                            "5xx": status_5xx
                        }
                    }
                }
                
                # Save results
                with open(result_filepath, 'w') as f:
                    json.dump(results, f, indent=4)
                
                # Update progress
                progress.complete(results)
                progress.message = f"Directory fuzzing completed. Found {status_2xx + status_3xx} accessible directories."
                
            except Exception as e:
                app.logger.error(f"Error during directory fuzzing: {str(e)}")
                progress.error(f"Error during fuzzing: {str(e)}")
        
        # Start the thread
        threading.Thread(target=run_fuzzing).start()
        
        flash(f"Starting directory fuzzing on {target_url}. This may take a moment...", "info")
        
        # Return the task ID for the client to poll progress
        return render_template('fuzzing_progress.html', 
                             task_id=task_id, 
                             task_type="directory",
                             target=target_url,
                             result_filename=result_filename)

    return render_template('directory_fuzzing.html')

@app.route('/subdomain_fuzzing', methods=['GET', 'POST'])
def subdomain_fuzzing():
    """Subdomain fuzzing page and functionality."""
    if request.method == 'POST':
        target_domain = request.form.get('target_domain', '').strip()
        use_wordlist = request.form.get('use_wordlist') == 'on'
        wordlist_file = request.files.get('wordlist_file')
        verify_ssl = request.form.get('verify_ssl') == 'on'

        # Validate domain
        if not target_domain:
            flash('Please enter a target domain', 'error')
            return redirect(url_for('subdomain_fuzzing'))

        # Remove http/https protocol if present
        target_domain = target_domain.replace('http://', '').replace('https://', '')
        
        # Remove trailing slashes and www if present
        target_domain = target_domain.rstrip('/').lower()
        if target_domain.startswith('www.'):
            target_domain = target_domain[4:]

        # Use uploaded wordlist or default list
        wordlist = []
        custom_wordlist_path = None
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            custom_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(custom_wordlist_path)

            # Load wordlist from file
            with open(custom_wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        else:
            # Use default wordlist from configuration
            with open("wordlists/subdomains.txt", 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()][:20]  # Limit to 20 for testing

        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"subdomains_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)

        # Initialize subdomain fuzzer
        fuzzer = SubdomainFuzzer(
            domain=target_domain,
            wordlist=wordlist,
            threads=5,
            delay=0.5,
            verify_ssl=verify_ssl
        )
        
        flash(f"Making HTTP requests to {len(wordlist)} subdomains. This may take a moment...", "info")
        
        # Run the fuzzing
        processed_urls = fuzzer.fuzz_subdomains()

        # Calculate statistics
        total_urls = len(processed_urls)
        def get_status(result):
            """Helper to get status from either status or status_code"""
            if isinstance(result.get('status_code'), int):
                return result.get('status_code')
            return result.get('status', 0)
            
        status_2xx = sum(1 for r in processed_urls if 200 <= get_status(r) < 300)
        status_3xx = sum(1 for r in processed_urls if 300 <= get_status(r) < 400)
        status_4xx = sum(1 for r in processed_urls if 400 <= get_status(r) < 500)
        status_5xx = sum(1 for r in processed_urls if 500 <= get_status(r) < 600)

        # Prepare results structure
        results = {
            "directories": [],
            "subdomains": processed_urls,
            "api_endpoints": [],
            "meta": {
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S'),
                "tool": "Web Application Fuzzer",
                "target_domain": target_domain,
                "total_urls": total_urls,
                "ssl_verification": verify_ssl,
                "status_summary": {
                    "2xx": status_2xx,
                    "3xx": status_3xx,
                    "4xx": status_4xx,
                    "5xx": status_5xx
                }
            }
        }

        # Save results
        with open(result_filepath, 'w') as f:
            json.dump(results, f, indent=4)

        flash(f"Subdomain fuzzing completed. Found {status_2xx} active subdomains.", "success")
        return redirect(url_for('results', filename=result_filename))

    return render_template('subdomain_fuzzing.html')

@app.route('/api_endpoints_fuzzing', methods=['GET', 'POST'])
def api_endpoints_fuzzing():
    """API endpoints fuzzing page and functionality."""
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        use_wordlist = request.form.get('use_wordlist') == 'on'
        wordlist_file = request.files.get('wordlist_file')
        http_methods = request.form.getlist('http_methods') or ['GET']  # Default to GET if none selected
        verify_ssl = request.form.get('verify_ssl') == 'on'

        # Validate URL
        if not target_url:
            flash('Please enter a target URL', 'error')
            return redirect(url_for('api_endpoints_fuzzing'))

        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"

        # Process wordlist
        endpoints = []
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(filepath)
            with open(filepath, 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()]
        else:
            # Use default wordlist from configuration
            with open("wordlists/api_endpoints.txt", 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()][:15]  # Limit to 15 for testing

        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"api_endpoints_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)
        
        app.logger.info(f"API endpoints fuzzing for {target_url} with {len(endpoints)} endpoints using {', '.join(http_methods)} methods")
        
        # Generate a unique task ID for progress tracking
        task_id = str(uuid.uuid4())
        
        # Create and store progress tracker
        progress = FuzzingProgress(task_id, "api_endpoint", total=len(endpoints) * len(http_methods))
        fuzzing_tasks[task_id] = progress
        
        # Start fuzzing in a background thread
        import threading
        def run_fuzzing():
            try:
                # Initialize API fuzzer
                fuzzer = ApiFuzzer(
                    base_url=target_url,
                    endpoints=endpoints,
                    methods=http_methods,
                    threads=5,
                    delay=0.5,
                    verify_ssl=verify_ssl
                )
                
                # Set the progress callback
                fuzzer.set_progress_callback(lambda completed, total, message: 
                    progress.update(
                        int((completed / 100) * progress.total) if completed <= 100 else completed, 
                        message
                    ))
                
                # Run the fuzzing
                fuzzing_results = fuzzer.fuzz_api_endpoints()
                
                # Convert results to the expected dictionary format
                processed_urls = []
                for result in fuzzing_results:
                    if result:
                        url, method, status_text = result
                        status_code = 200 if status_text == 'valid' else (
                                    403 if status_text == 'forbidden' else 
                                    404 if status_text == 'not_found' else 
                                    500 if status_text == 'server_error' else 0)
                                    
                        # Convert the tuple result to dictionary format
                        result_dict = {
                            'url': url,
                            'method': method,
                            'status': status_code,
                            'status_text': status_text,
                            'size': 'N/A',
                            'response_time': 'N/A',
                            'content_type': 'N/A',
                            'auth_required': status_text == 'forbidden'
                        }
                        processed_urls.append(result_dict)
                        
                # Calculate statistics
                total_urls = len(processed_urls)
                def get_status(result):
                    """Helper to get status from either status or status_code"""
                    return result.get('status', 0)
                    
                status_2xx = sum(1 for r in processed_urls if 200 <= get_status(r) < 300)
                status_3xx = sum(1 for r in processed_urls if 300 <= get_status(r) < 400)
                status_4xx = sum(1 for r in processed_urls if 400 <= get_status(r) < 500)
                status_5xx = sum(1 for r in processed_urls if 500 <= get_status(r) < 600)
                auth_required = sum(1 for r in processed_urls if r.get('auth_required', False))

                # Prepare results structure
                results = {
                    "meta": {
                        "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "tool": "Web Application Fuzzer",
                        "target_url": target_url,
                        "total_endpoints": len(endpoints),
                        "http_methods": http_methods,
                        "status_summary": {
                            "2xx": status_2xx,
                            "3xx": status_3xx,
                            "4xx": status_4xx,
                            "5xx": status_5xx,
                            "auth_required": auth_required
                        }
                    },
                    "api_endpoints": processed_urls
                }

                # Save results
                with open(result_filepath, 'w') as f:
                    json.dump(results, f, indent=4)
                
                app.logger.info(f"API endpoints fuzzing completed for {target_url}. Saved to {result_filepath}")
                
                # Set progress to complete with results
                progress.complete(results)
                
            except Exception as e:
                error_msg = f"Error during API endpoints fuzzing: {str(e)}"
                app.logger.error(error_msg)
                progress.error(error_msg)
        
        # Start the background thread
        threading.Thread(target=run_fuzzing).start()
        
        flash(f"Starting API endpoint fuzzing for {target_url}. This may take a moment...", "info")
        
        # Redirect to a page that will show the progress and eventually the results
        return render_template('fuzzing_progress.html', 
                              task_id=task_id, 
                              task_type="API Endpoint", 
                              target=target_url,
                              result_filename=result_filename)

    return render_template('api_endpoints_fuzzing.html')

@app.route('/virtualhost_fuzzing', methods=['GET', 'POST'])
def virtualhost_fuzzing():
    if request.method == 'POST':
        # Start the fuzzing process (this should call your fuzzer's logic)
        
        if request.method == 'POST':
            target_ip = request.form.get('target_ip', '').strip()
            use_wordlist = request.form.get('use_wordlist') == 'on'
            wordlist_file = request.files.get('wordlist_file')

        if not target_ip:
            flash('Please enter a target IP address', 'error')
            return redirect(url_for('virtualhost_fuzzing'))

        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            custom_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(custom_wordlist_path)

            with open(custom_wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        else:
            flash("Please upload a valid wordlist file", "error")
            return redirect(url_for('virtualhost_fuzzing'))

        # Run the fuzzer
        try:
            from src.fuzzing.virtual_hosts import VirtualHostFuzzer  # adjust import path
            fuzzer = VirtualHostFuzzer(target_ip=target_ip, wordlist=wordlist)
            results = fuzzer.fuzz()
        except Exception as e:
            flash(f"Fuzzing failed: {str(e)}", "error")
            return redirect(url_for('virtualhost_fuzzing'))
        # Process the results
        processed_urls = []
        status_code_counts = {
            '2xx': 0,
            '3xx': 0,
            '4xx': 0,
            '5xx': 0,
            'redirected': 0
        }
        
        for result in results:
            if result:
                # Extract necessary fields from the result dictionary
                domain = result.get('domain', '')
                status_code = result.get('status_code', 0)
                title = result.get('title', '')
                content_length = result.get('content_length', 'N/A')
                response_time = result.get('response_time', 'N/A')
                headers = result.get('headers', {})
                is_redirected = result.get('is_redirected', False)

                # Classify status codes for summary
                if 200 <= status_code < 300:
                    status_code_counts['2xx'] += 1
                elif 300 <= status_code < 400:
                    status_code_counts['3xx'] += 1
                elif 400 <= status_code < 500:
                    status_code_counts['4xx'] += 1
                elif 500 <= status_code < 600:
                    status_code_counts['5xx'] += 1
                if is_redirected:
                    status_code_counts['redirected'] += 1
                
                # Build the result dictionary
                processed_urls.append({
                    'domain': domain,
                    'status_code': status_code,
                    'title': title,
                    'content_length': content_length,
                    'response_time': response_time,
                    'headers': headers,
                    'is_redirected': is_redirected
                })

        # Prepare results structure
        results = {
            "virtual_hosts": processed_urls,
            "status_code_summary": status_code_counts,
            "meta": {
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S'),
                "tool": "Web Application Fuzzer"
            },
            "results": results
        }

        # Save results to file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"virtualhosts_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)
        with open(result_filepath, 'w') as f:
            # Compute status summary
            summary = {
                "2xx": 0,
                "3xx": 0,
                "4xx": 0,
                "5xx": 0,
                "redirected": 0
            }

            for result in results["results"]:
                code = result.get("status_code", 0)

                if 200 <= code < 300:
                    summary["2xx"] += 1
                elif 300 <= code < 400:
                    summary["3xx"] += 1
                elif 400 <= code < 500:
                    summary["4xx"] += 1
                elif 500 <= code < 600:
                    summary["5xx"] += 1

                if result.get("is_redirected"):
                    summary["redirected"] += 1

            # Inject it into the results
            results["status_code_summary"] = summary

            json.dump(results, f, indent=4)

        # Flash the result to the user
        flash(f"Virtual host fuzzing completed. Found {status_code_counts['2xx']} accessible virtual hosts, {status_code_counts['redirected']} redirected.", "success")
        
        # Return the results page
        return redirect(url_for('results', filename=result_filename))

    return render_template('virtualhost_fuzzing.html')

@app.route('/parameter_fuzzing', methods=['GET', 'POST'])
def parameter_fuzzing():
    if request.method == 'POST':
        # Get the target URL from the form
        target_url = request.form.get('target_url', '')
        
        # Log the received URL
        app.logger.info(f"Parameter fuzzing requested for URL: {target_url}")
        
        # Validate URL
        if not target_url:
            flash('Please enter a target URL.', 'error')
            return render_template('parameter_fuzzing.html')
        
        # Add https:// if no protocol specified
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = 'https://' + target_url
            app.logger.info(f"Added HTTPS protocol to URL: {target_url}")
        
        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d_%H%M%S')
        result_file = f"results/parameters_{timestamp}.json"
        app.logger.info(f"Creating result file: {result_file}")
        
        # Generate a unique task ID for progress tracking
        task_id = str(uuid.uuid4())
        
        # Create and store progress tracker
        progress = FuzzingProgress(task_id, "parameter", total=100)  # We'll update the total later
        fuzzing_tasks[task_id] = progress
        
        # Initialize the parameter fuzzer
        app.logger.info(f"ParameterFuzzer initialized with URL: {target_url}")
        fuzzer = ParameterFuzzer(
            target_url=target_url,
            async_requests=10,
            timeout=5,
            request_delay=0.1
        )
        
        # Set the progress callback
        fuzzer.set_progress_callback(lambda completed, total, message: 
            progress.update(
                int((completed / 100) * progress.total) if completed <= 100 else completed, 
                message
            ))
        
        # Start fuzzing in a background thread
        import threading
        def run_fuzzing():
            try:
                # Run the fuzzing process
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(fuzzer.run())
                loop.close()
                
                app.logger.info(f"Fuzzing completed with {len(results)} results")
                
                # Calculate statistics
                total_params_tested = len(results) if results else 0
                vulnerable_params = sum(1 for r in results if r.get('score', 0) > 3)
                
                # Process results for the parameters section format
                app.logger.info(f"Processing {total_params_tested} results")
                processed_results = []
                for result in results:
                    processed_results.append({
                        'url': result.get('url', ''),
                        'param': result.get('param', ''),
                        'payload': result.get('payload', ''),
                        'category': result.get('category', ''),
                        'status': result.get('status', 0),
                        'score': result.get('score', 0),
                        'evidence': result.get('evidence', []),
                        'size': result.get('size', 0),
                        'response_time': result.get('response_time', 0)
                    })
                    
                # Save results to file in standard format
                os.makedirs(os.path.dirname(result_file), exist_ok=True)
                final_results = {
                    'meta': {
                        'timestamp': dt.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'tool': 'Web Application Fuzzer',
                        'target_url': target_url,
                        'total_params_tested': total_params_tested,
                        'vulnerable_params': vulnerable_params
                    },
                    'parameters': processed_results
                }
                    
                with open(result_file, 'w') as f:
                    json.dump(final_results, f, indent=4)
                    
                app.logger.info(f"Results saved to {result_file}")
                
                # Mark progress as complete
                progress.complete(final_results)
                
            except Exception as e:
                error_msg = f"Error during parameter fuzzing: {str(e)}"
                app.logger.error(error_msg)
                progress.error(error_msg)
                
        # Start the thread for background processing
        threading.Thread(target=run_fuzzing).start()
        
        # Redirect to progress page
        return render_template('fuzzing_progress.html', 
                              task_id=task_id, 
                              task_type="Parameter", 
                              target=target_url,
                              result_filename=os.path.basename(result_file))
    
    return render_template('parameter_fuzzing.html')

# Routes
@app.route('/results_list')
def results_list():
    """List all result files"""
    result_files = []
    for filename in os.listdir(app.config['RESULT_FOLDER']):
        if filename.endswith('.json'):
            file_path = os.path.join(app.config['RESULT_FOLDER'], filename)
            created_time = os.path.getctime(file_path)
            created_date = dt.fromtimestamp(created_time).strftime('%Y-%m-%d %H:%M:%S')
            
            # Determine the type of fuzzing from the filename
            fuzz_type = filename.split('_')[0]
            
            result_files.append({
                'filename': filename,
                'created': created_date,
                'type': fuzz_type
            })
    
    # Sort by most recent first
    result_files.sort(key=lambda x: x['created'], reverse=True)
    
    return render_template('results_list.html', result_files=result_files)
@app.route('/results/<filename>')
def results(filename):
    """Display results page for a specific result file."""
    try:
        result_path = os.path.join(app.config['RESULT_FOLDER'], filename)
        with open(result_path, 'r') as f:
            result_data = json.load(f)

        target_url = result_data.get('meta', {}).get('target_url', 'Unknown')
        
        # Determine fuzzing type from the filename
        fuzzing_type = 'Unknown'
        if 'director' in filename:
            fuzzing_type = 'Directory'
            # Check both possible keys for directory results
            results_list = result_data.get('directories', [])
            if not results_list and isinstance(result_data.get('results', []), list):
                results_list = result_data.get('results', [])
        elif 'subdomain' in filename:
            fuzzing_type = 'Subdomain'
            results_list = result_data.get('subdomains', [])
            if not results_list and isinstance(result_data.get('results', []), list):
                results_list = result_data.get('results', [])
        elif 'api_endpoints' in filename:
            fuzzing_type = 'API Endpoint'
            results_list = result_data.get('api_endpoints', [])
            if not results_list and isinstance(result_data.get('results', []), list):
                results_list = result_data.get('results', [])
        elif 'parameter' in filename:
            fuzzing_type = 'Parameter'
            results_list = result_data.get('parameters', [])
            if not results_list and isinstance(result_data.get('results', []), list):
                results_list = result_data.get('results', [])
        elif 'virtualhost' in filename:
            fuzzing_type = 'Virtual Host'
            results_list = result_data.get('virtualhosts', [])
            # Check alternative keys if the expected one isn't found
            if not results_list and isinstance(result_data.get('hosts', []), list):
                results_list = result_data.get('hosts', [])
            if not results_list and isinstance(result_data.get('results', []), list):
                results_list = result_data.get('results', [])
        else:
            # Generic fallback - try to find results data
            app.logger.info(f"Unknown fuzzing type for file {filename}, attempting to extract results")
            results_list = []
            for key in ['results', 'directories', 'subdomains', 'api_endpoints', 'parameters', 'virtualhosts', 'hosts']:
                if isinstance(result_data.get(key, []), list):
                    results_list = result_data.get(key, [])
                    app.logger.info(f"Found results under key: {key}")
                    break
        
        app.logger.info(f"Determined fuzzing type: {fuzzing_type}")
        app.logger.info(f"Found {len(results_list)} processed results")
        app.logger.info(f"Target URL: {target_url}")

        # Calculate status counts
        total_urls = len(results_list)
        
        def get_status(result):
            """Helper to get status from either status or status_code"""
            if 'status' in result:
                return result['status']
            return result.get('status_code', 0)
            
        status_2xx = sum(1 for r in results_list if 200 <= get_status(r) < 300)
        status_3xx = sum(1 for r in results_list if 300 <= get_status(r) < 400)
        status_4xx = sum(1 for r in results_list if 400 <= get_status(r) < 500)
        status_5xx = sum(1 for r in results_list if 500 <= get_status(r) < 600)

        app.logger.info(f"Status summary: 2xx={status_2xx}, 3xx={status_3xx}, 4xx={status_4xx}, 5xx={status_5xx}")

        return render_template(
            'results.html',
            filename=filename,
            fuzzing_type=fuzzing_type,
            target_url=target_url,
            results=results_list,
            total_urls=total_urls,
            status_2xx=status_2xx,
            status_3xx=status_3xx,
            status_4xx=status_4xx,
            status_5xx=status_5xx,
            additional_data=None if fuzzing_type != 'Parameter' else {
                'vulnerable_params': sum(1 for r in results_list if r.get('score', 0) >= 3),
                'param_categories': {
                    category: sum(1 for r in results_list if r.get('category', 'Unknown') == category)
                    for category in set(r.get('category', 'Unknown') for r in results_list)
                }
            }
        )
    except Exception as e:
        app.logger.error(f"Error displaying results: {str(e)}")
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('results_list'))

@app.route('/download_results/<filename>')
def download_results(filename):
    """Download the results file."""
    try:
        return send_from_directory(
            app.config['RESULT_FOLDER'],
            filename,
            as_attachment=True,
            mimetype='application/json'
        )
    except FileNotFoundError:
        flash("Results file not found.", "error")
        return redirect(url_for('index'))

@app.route('/export_csv/<filename>')
def export_csv(filename):
    """Export results as CSV file for download"""
    filepath = os.path.join(app.config['RESULT_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        flash('Results file not found', 'error')
        return redirect(url_for('index'))
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Determine the type of results based on filename
    fuzz_type = filename.split('_')[0]
    
    # Process results based on fuzz type
    if fuzz_type == 'directories':
        urls = data.get('directories', [])
        fieldnames = ['url', 'status', 'size', 'response_time', 'content_type']
    elif fuzz_type == 'subdomains':
        urls = data.get('subdomains', [])
        fieldnames = ['url', 'status', 'size', 'response_time', 'content_type']
    elif fuzz_type == 'api_endpoints':
        urls = data.get('api_endpoints', [])
        fieldnames = ['url', 'method', 'status', 'size', 'response_time', 'content_type', 'auth_required']
    elif fuzz_type == 'parameters':
        # For parameter fuzzing, check both formats
        if 'parameters' in data:
            urls = data.get('parameters', [])
        else:
            urls = data.get('results', [])
        fieldnames = ['url', 'param', 'payload', 'category', 'status', 'score', 'evidence', 'size', 'response_time']
    else:
        urls = []
        fieldnames = ['url', 'status', 'size', 'response_time', 'content_type']
    
    # Create processed results list with uniform structure
    processed_results = []
    for url in urls:
        if isinstance(url, dict):
            # URL already has status information
            processed_results.append(url)
        else:
            # URL is just a string, add placeholder values
            processed_results.append({
                'url': url,
                'status': 'N/A',
                'size': 'N/A',
                'response_time': 'N/A',
                'content_type': 'N/A'
            })
    
    # Create CSV data
    csv_data = StringIO()
    writer = csv.DictWriter(csv_data, fieldnames=fieldnames)
    writer.writeheader()
    
    for result in processed_results:
        row = {}
        for field in fieldnames:
            if field == 'evidence' and isinstance(result.get(field), list):
                row[field] = ', '.join(result.get(field, []))
            else:
                row[field] = result.get(field, 'N/A')
        writer.writerow(row)
    
    # Create response with CSV data
    response = make_response(csv_data.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename.rsplit(".", 1)[0]}.csv'
    response.headers['Content-Type'] = 'text/csv'
    
    return response

@app.route('/export_json/<filename>')
def export_json(filename):
    """Export results as JSON file for download"""
    filepath = os.path.join(app.config['RESULT_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        flash('Results file not found', 'error')
        return redirect(url_for('index'))
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Create response with JSON data
    response = make_response(json.dumps(data, indent=4))
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'application/json'
    
    return response

@app.route('/update_all_urls/<filename>')
async def update_all_urls(filename):
    """Update all URLs in a result file with status codes, sizes, and other information"""
    filepath = os.path.join(app.config['RESULT_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        flash('Results file not found', 'error')
        return redirect(url_for('index'))
    
    # Load the results file
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Determine the type of results based on filename
    fuzz_type = filename.split('_')[0]
    
    # Get the appropriate URL list
    if fuzz_type == 'directories':
        urls = data.get('directories', [])
    elif fuzz_type == 'subdomains':
        urls = data.get('subdomains', [])
    elif fuzz_type == 'api_endpoints':
        urls = data.get('api_endpoints', [])
    else:
        flash('Unsupported fuzzing type', 'error')
        return redirect(url_for('results_list'))
    
    # Get verify_ssl from meta data if available, default to True
    verify_ssl = data.get('meta', {}).get('ssl_verification', True)
    
    # Create a request handler
    request_handler = RequestHandler()
    
    # Process each URL
    processed_urls = []
    total_urls = len(urls)
    updated_count = 0
    
    # Create async tasks for all URLs
    async def process_url(url_obj):
        # Check if URL is already a dict with status information
        if isinstance(url_obj, dict) and url_obj.get('status') not in ['N/A', 'Error']:
            return url_obj
            
        # Get the URL string
        url_str = url_obj if isinstance(url_obj, str) else url_obj.get('url', '')
        
        # Skip empty URLs
        if not url_str:
            return None
            
        # Make request and get result
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=verify_ssl)) as session:
                start_time = dt.now()
                async with session.get(url_str, timeout=10) as response:
                    response_time = (dt.now() - start_time).total_seconds()
                    content = await response.read()
                    
                    result = {
                        'url': url_str,
                        'status': response.status,
                        'size': len(content),
                        'response_time': f"{response_time:.2f}s",
                        'content_type': response.headers.get('Content-Type', 'N/A')
                    }
                    return result
        except Exception as e:
            # If error, add URL with error info
            error_result = {
                'url': url_str,
                'status': 'Error',
                'size': 'N/A',
                'response_time': 'N/A',
                'content_type': 'N/A',
                'error': str(e)
            }
            return error_result
    
    # Create and run tasks for all URLs
    tasks = []
    for url in urls:
        tasks.append(process_url(url))
        
    # Wait for all tasks to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for result in results:
        if result is not None:
            processed_urls.append(result)
            if isinstance(result, dict) and result.get('status') != 'Error':
                updated_count += 1
    
    # Update the appropriate section in the data
    if fuzz_type == 'directories':
        data['directories'] = processed_urls
    elif fuzz_type == 'subdomains':
        data['subdomains'] = processed_urls
    elif fuzz_type == 'api_endpoints':
        data['api_endpoints'] = processed_urls
    
    # Save the updated data
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    
    # Add a success message
    flash(f'Successfully updated {updated_count} of {total_urls} URLs', 'success')
    
    # Redirect to the results page
    return redirect(url_for('results', filename=filename))

# New settings routes
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Settings page for application configuration."""
    global app_config
    
    if request.method == 'POST':
        try:
            # Extract form data
            new_config = {
                "target_url": request.form.get('target_url', ''),
                "target_domain": request.form.get('target_domain', ''),
                "directories": {
                    "enabled": request.form.get('directories_enabled') == 'on',
                    "wordlist": app_config['directories'].get('wordlist', 'wordlists/directory_wordlist.txt')
                },
                "subdomains": {
                    "enabled": request.form.get('subdomains_enabled') == 'on',
                    "wordlist": app_config['subdomains'].get('wordlist', 'wordlists/subdomain_wordlist.txt')
                },
                "api_endpoints": {
                    "enabled": request.form.get('api_endpoints_enabled') == 'on',
                    "wordlist": app_config['api_endpoints'].get('wordlist', 'wordlists/api_endpoints.txt')
                },
                "parameter_fuzzing": {
                    "enabled": request.form.get('parameter_fuzzing_enabled') == 'on',
                    "wordlist": app_config['parameter_fuzzing'].get('wordlist', 'wordlists/parameter_wordlist.txt')
                },
                "request_options": {
                    "method": request.form.get('request_method', 'GET'),
                    "timeout": int(request.form.get('timeout', 10)),
                    "retries": int(request.form.get('retries', 3))
                },
                "rate_limiting": {
                    "enabled": request.form.get('rate_limiting_enabled') == 'on',
                    "requests_per_second": int(request.form.get('requests_per_second', 5))
                },
                "logging": {
                    "enabled": request.form.get('logging_enabled') == 'on',
                    "log_file": request.form.get('log_file', 'fuzzer_log.log')
                }
            }
            
            # Save the configuration
            if save_config(new_config):
                app_config = new_config  # Update the in-memory config
                flash("Settings saved successfully", "success")
            else:
                flash("Error saving settings", "error")
                
        except Exception as e:
            app.logger.error(f"Error processing settings form: {str(e)}")
            flash(f"Error processing settings: {str(e)}", "error")
        
        return redirect(url_for('settings'))
    
    # GET request - show the settings page
    return render_template('settings.html', config=app_config)

@app.route('/reset_settings')
def reset_settings():
    """Reset settings to defaults."""
    global app_config
    
    try:
        # Copy default config to current config
        if os.path.exists(app.config['DEFAULT_CONFIG_FILE']):
            shutil.copy(app.config['DEFAULT_CONFIG_FILE'], app.config['CONFIG_FILE'])
            app_config = load_config()  # Reload the config
            flash("Settings have been reset to defaults", "success")
        else:
            flash("Default configuration file not found", "error")
    except Exception as e:
        app.logger.error(f"Error resetting settings: {str(e)}")
        flash(f"Error resetting settings: {str(e)}", "error")
    
    return redirect(url_for('settings'))

# New endpoint to check fuzzing progress
@app.route('/fuzzing_progress/<task_id>')
def fuzzing_progress(task_id):
    global fuzzing_tasks
    if task_id in fuzzing_tasks:
        return jsonify(fuzzing_tasks[task_id].to_dict())
    else:
        return jsonify({"error": "Task not found"}), 404

if __name__ == '__main__':
    app.logger.info("Directory fuzzing enabled!") if app_config['directories']['enabled'] else None
    app.logger.info("SubDomain fuzzing enabled!") if app_config['subdomains']['enabled'] else None
    app.logger.info("API Endpoints fuzzing enabled!") if app_config['api_endpoints']['enabled'] else None
    app.logger.info("Parameter Fuzzing enabled!") if app_config.get('parameter_fuzzing', {}).get('enabled', False) else None
    app.run(host='0.0.0.0')

