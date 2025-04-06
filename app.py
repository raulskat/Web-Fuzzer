#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime as dt
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, make_response
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import os
import json
import csv
from io import StringIO
import requests

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'
app.secret_key = 'your-secret-key'  # Change this in production

# Create directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)
# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}

def generate_subdomains(count=20):
    common_subdomains = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
        'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'admin',
        'ftp', 'cloud', 'portal', 'support'
    ]
    
    # Return a subset or the whole list based on requested size
    return common_subdomains[:min(count, len(common_subdomains))]

def generate_api_endpoints(count=15):
    common_endpoints = [
        'api/v1', 'api/v2', 'api/users', 'api/products', 'api/auth', 
        'api/login', 'api/register', 'api/data', 'api/search', 'api/settings',
        'api/admin', 'api/files', 'api/upload', 'api/config', 'api/stats'
    ]
    
    # Return a subset or the whole list based on requested size
    return common_endpoints[:min(count, len(common_endpoints))]
class RequestHandler:
    def __init__(self, verify_ssl=True):
        self.headers = {
            'User-Agent': 'Web-Fuzzer/1.0',
            'Accept': '*/*'
        }
        self.timeout = 10
        self.verify_ssl = verify_ssl

    def send_request(self, url):
        """Send HTTP request to a URL."""
        try:
            start_time = dt.now()
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout, 
                allow_redirects=False,
                verify=self.verify_ssl
            )
            elapsed_time = (dt.now() - start_time).total_seconds() * 1000  # Convert to milliseconds
            
            # Extract domain and path for logging
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            log_message = f"Request to {domain}{path}: Status {response.status_code}, Size {len(response.content)} bytes, Time {int(elapsed_time)}ms"
            if response.status_code >= 400:
                app.logger.warning(log_message)
            else:
                app.logger.info(log_message)
            
            return {
                "url": url,
                "status": response.status_code,
                "size": len(response.content),
                "response_time": int(elapsed_time),
                "content_type": response.headers.get('Content-Type', 'N/A'),
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.RequestException as e:
            error_type = type(e).__name__
            error_message = str(e)
            
            # Extract domain and path for logging
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            app.logger.error(f"Error requesting {domain}{path}: {error_type}: {error_message}")
            
            return {
                "url": url,
                "status": "Error",
                "size": "N/A",
                "response_time": "N/A",
                "content_type": "N/A",
                "error": str(e),
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    def send_request_api(self, base_url, endpoint, method='GET'):
        """Send request to API endpoint.
        Args:
            base_url (str): The base URL (e.g., https://example.com)
            endpoint (str): The API endpoint (e.g., api/v1)
            method (str): HTTP method to use (default: GET)
        """
        # Remove any hash from base_url
        base_url = base_url.split('#')[0].rstrip('/')
        
        # Ensure proper URL construction
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"https://{base_url}"
        
        endpoint = endpoint.lstrip('/')
        url = f"{base_url}/{endpoint}"
        
        try:
            start_time = dt.now()
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl
            )
            elapsed_time = (dt.now() - start_time).total_seconds() * 1000

            # Extract domain and path for logging
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path

            log_message = f"[{method}] {domain}{path}: Status {response.status_code}, Size {len(response.content)} bytes, Time {int(elapsed_time)}ms"
            
            if response.status_code == 401:
                app.logger.info(f"{log_message} (Auth required)")
            elif response.status_code >= 400:
                app.logger.warning(log_message)
            else:
                app.logger.info(log_message)
                
            return {
                "url": url,
                "method": method,
                "status": response.status_code,
                "size": len(response.content),
                "response_time": int(elapsed_time),
                "content_type": response.headers.get('Content-Type', 'N/A'),
                "auth_required": response.status_code == 401,
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.RequestException as e:
            error_type = type(e).__name__
            error_message = str(e)
            
            # Extract domain and path for logging
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            app.logger.error(f"Error requesting [{method}] {domain}{path}: {error_type}: {error_message}")
            
            return {
                "url": url,
                "method": method,
                "status": "Error",
                "size": 0,
                "response_time": 0,
                "content_type": "N/A",
                "error": f"{error_type}: {error_message}",
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S')
            }
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
        wordlist_file = request.files.get('wordlist_file')
        verify_ssl = request.form.get('verify_ssl') == 'on'

        # Validate URL
        if not target_url:
            flash('Please enter a target URL', 'error')
            return redirect(url_for('directory_fuzzing'))

        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"

        # Use uploaded wordlist or generate a default one
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(filepath)

            with open(filepath, 'r') as f:
                directories = [line.strip() for line in f if line.strip()]
        else:
            # Use default directory list
            directories = [
                'admin', 'wp-admin', 'wp-content', 'upload', 'uploads', 'backup',
                'backups', 'config', 'dashboard', 'login', 'wp-login.php', 'administrator',
                'phpmyadmin', 'panel', 'cpanel', 'webmail', 'mail', 'api', 'docs',
                'documentation', 'blog', 'admin.php', 'old', 'test', 'staging'
            ]

        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"directories_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)

        # Create request handler
        request_handler = RequestHandler(verify_ssl=verify_ssl)

        # Make HTTP requests
        processed_urls = []
        flash(f"Making HTTP requests to {len(directories)} directories. This may take a moment...", "info")

        for directory in directories:
            # Remove leading/trailing slashes
            directory = directory.strip('/')
            url = f"{target_url}/{directory}"
            result = request_handler.send_request(url)
            processed_urls.append(result)

        # Calculate statistics
        total_urls = len(processed_urls)
        status_2xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 200 <= r.get('status', 0) < 300)
        status_3xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 300 <= r.get('status', 0) < 400)
        status_4xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 400 <= r.get('status', 0) < 500)
        status_5xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 500 <= r.get('status', 0) < 600)

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

        flash(f"Directory fuzzing completed. Found {status_2xx + status_3xx} accessible directories.", "success")
        return redirect(url_for('results', filename=result_filename))

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

        # Use uploaded wordlist or generate one
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(filepath)

            with open(filepath, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        else:
            subdomains = generate_subdomains(20)

        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"subdomains_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)

        # Create request handler
        request_handler = RequestHandler(verify_ssl=verify_ssl)

        # Make HTTP requests
        processed_urls = []
        flash(f"Making HTTP requests to {len(subdomains)} subdomains. This may take a moment...", "info")

        for subdomain in subdomains:
            url = f"https://{subdomain}.{target_domain}"
            result = request_handler.send_request(url)
            processed_urls.append(result)

        # Calculate statistics
        total_urls = len(processed_urls)
        status_2xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 200 <= r.get('status', 0) < 300)
        status_3xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 300 <= r.get('status', 0) < 400)
        status_4xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 400 <= r.get('status', 0) < 500)
        status_5xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 500 <= r.get('status', 0) < 600)

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
        verify_ssl = request.form.get('verify_ssl') == 'on'  # Get SSL verification preference

        # Validate URL
        if not target_url:
            flash('Please enter a target URL', 'error')
            return redirect(url_for('api_endpoints_fuzzing'))

        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"

        # Use uploaded wordlist or generate one
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(filepath)

            with open(filepath, 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()]
        else:
            endpoints = generate_api_endpoints(15)

        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"api_endpoints_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)

        # Create request handler
        request_handler = RequestHandler(verify_ssl=verify_ssl)

        # Make HTTP requests to each endpoint with each method
        processed_urls = []
        flash(f"Making HTTP requests to {len(endpoints)} API endpoints with {len(http_methods)} HTTP methods. This may take a moment...", "info")

        for endpoint in endpoints:
            for method in http_methods:
                result = request_handler.send_request_api(target_url, endpoint, method)
                processed_urls.append(result)

        # Calculate statistics
        total_urls = len(processed_urls)
        status_2xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 200 <= r.get('status', 0) < 300)
        status_3xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 300 <= r.get('status', 0) < 400)
        status_4xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 400 <= r.get('status', 0) < 500)
        status_5xx = sum(1 for r in processed_urls if isinstance(r.get('status'), int) and 500 <= r.get('status', 0) < 600)
        auth_required = sum(1 for r in processed_urls if r.get('auth_required', False))

        # Prepare results structure
        results = {
            "directories": [],
            "subdomains": [],
            "api_endpoints": processed_urls,
            "meta": {
                "timestamp": dt.now().strftime('%Y-%m-%d %H:%M:%S'),
                "tool": "Web Application Fuzzer",
                "target_url": target_url,
                "total_urls": total_urls,
                "http_methods": http_methods,
                "status_summary": {
                    "2xx": status_2xx,
                    "3xx": status_3xx,
                    "4xx": status_4xx,
                    "5xx": status_5xx,
                    "auth_required": auth_required
                }
            }
        }

        # Save results
        with open(result_filepath, 'w') as f:
            json.dump(results, f, indent=4)

        flash(f"API endpoint fuzzing completed. Found {status_2xx} accessible endpoints, {auth_required} requiring authentication.", "success")
        return redirect(url_for('results', filename=result_filename))

    return render_template('api_endpoints_fuzzing.html')

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
    """Display results from a JSON file."""
    try:
        result_path = os.path.join(app.config['RESULT_FOLDER'], filename)
        with open(result_path, 'r') as f:
            results_data = json.load(f)
        
        # Determine fuzzing type and get results
        if 'api_endpoints' in filename:
            fuzzing_type = "API Endpoint"
            processed_results = results_data['api_endpoints']
        elif 'directories' in filename:
            fuzzing_type = "Directory"
            processed_results = results_data['directories']
        elif 'subdomains' in filename:
            fuzzing_type = "Subdomain"
            processed_results = results_data['subdomains']
        else:
            fuzzing_type = "Unknown"
            processed_results = []

        # Calculate status summary
        status_2xx = sum(1 for r in processed_results if isinstance(r.get('status'), int) and 200 <= r.get('status', 0) < 300)
        status_3xx = sum(1 for r in processed_results if isinstance(r.get('status'), int) and 300 <= r.get('status', 0) < 400)
        status_4xx = sum(1 for r in processed_results if isinstance(r.get('status'), int) and 400 <= r.get('status', 0) < 500)
        status_5xx = sum(1 for r in processed_results if isinstance(r.get('status'), int) and 500 <= r.get('status', 0) < 600)

        # Get target URL from meta if available
        target_url = results_data.get('meta', {}).get('target_url', '')

        return render_template(
            'results.html',
            target_url=target_url,
            results=processed_results,
            fuzzing_type=fuzzing_type,
            total_urls=len(processed_results),
            status_2xx=status_2xx,
            status_3xx=status_3xx,
            status_4xx=status_4xx,
            status_5xx=status_5xx,
            filename=filename
        )
    except (FileNotFoundError, json.JSONDecodeError) as e:
        app.logger.error(f"Error loading results file {filename}: {str(e)}")
        flash(f"Error loading results: {str(e)}", "error")
        flash(f"Error loading results: {str(e)}", "error")
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
    
    # Process results based on fuzz type (directories, subdomains, api_endpoints)
    if fuzz_type == 'directories':
        urls = data.get('directories', [])
    elif fuzz_type == 'subdomains':
        urls = data.get('subdomains', [])
    elif fuzz_type == 'api_endpoints':
        urls = data.get('api_endpoints', [])
    else:
        urls = []
    
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
    fieldnames = ['url', 'status', 'size', 'response_time', 'content_type']
    
    writer = csv.DictWriter(csv_data, fieldnames=fieldnames)
    writer.writeheader()
    
    for result in processed_results:
        row = {
            'url': result.get('url', ''),
            'status': result.get('status', 'N/A'),
            'size': result.get('size', 'N/A'),
            'response_time': result.get('response_time', 'N/A'),
            'content_type': result.get('content_type', 'N/A')
        }
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
def update_all_urls(filename):
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
    
    # Create a request handler
    request_handler = RequestHandler()
    
    # Process each URL
    processed_urls = []
    total_urls = len(urls)
    updated_count = 0
    
    for i, url in enumerate(urls):
        # Check if URL is already a dict with status information
        if isinstance(url, dict) and url.get('status') not in ['N/A', 'Error']:
            processed_urls.append(url)
            continue
            
        # Get the URL string
        url_str = url if isinstance(url, str) else url.get('url', '')
        
        # Skip empty URLs
        if not url_str:
            continue
            
        # Make request and get result
        try:
            result = request_handler.send_request(url_str)
            processed_urls.append(result)
            updated_count += 1
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
            processed_urls.append(error_result)
    
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
# Routes
# These routes are already defined above


if __name__ == '__main__':
    app.run(debug=True)

