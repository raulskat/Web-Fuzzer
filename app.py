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
import asyncio
import aiohttp
from src.fuzzing.directories import DirectoryFuzzer
from src.fuzzing.subdomains import SubdomainFuzzer
from src.fuzzing.api_endpoints import ApiFuzzer
from src.utils.request_handler import RequestHandler

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

        # Generate timestamp for results file
        timestamp = dt.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"directories_{timestamp}.json"
        result_filepath = os.path.join(app.config['RESULT_FOLDER'], result_filename)

        # Process wordlist
        custom_wordlist_path = None
        if use_wordlist and wordlist_file and allowed_file(wordlist_file.filename):
            filename = secure_filename(wordlist_file.filename)
            custom_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(custom_wordlist_path)

        # Initialize directory fuzzer
        fuzzer = DirectoryFuzzer(
            target_url=target_url,
            wordlist_source="predefined",
            custom_wordlist_path=custom_wordlist_path,
            verify_ssl=verify_ssl
        )
        
        flash(f"Starting directory fuzzing on {target_url}. This may take a moment...", "info")
        
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

        # Initialize API fuzzer
        fuzzer = ApiFuzzer(
            base_url=target_url,
            endpoints=endpoints,
            methods=http_methods,
            threads=5,
            delay=0.5,
            verify_ssl=verify_ssl
        )

        flash(f"Making HTTP requests to {len(endpoints)} API endpoints with {len(http_methods)} HTTP methods. This may take a moment...", "info")

        # Run the fuzzing
        fuzzing_results = fuzzer.fuzz_api_endpoints()
        
        # Convert results to the expected dictionary format
        processed_urls = []
        for result in fuzzing_results:
            if result:
                url, method, status_text = result
                # Convert the tuple result to dictionary format
                result_dict = {
                    'url': url,
                    'method': method,
                    'status': 200 if status_text == 'valid' else 
                              403 if status_text == 'forbidden' else 
                              404 if status_text == 'not_found' else 
                              500 if status_text == 'server_error' else 0,
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
            if isinstance(result.get('status_code'), int):
                return result.get('status_code')
            return result.get('status', 0)
            
        status_2xx = sum(1 for r in processed_urls if 200 <= get_status(r) < 300)
        status_3xx = sum(1 for r in processed_urls if 300 <= get_status(r) < 400)
        status_4xx = sum(1 for r in processed_urls if 400 <= get_status(r) < 500)
        status_5xx = sum(1 for r in processed_urls if 500 <= get_status(r) < 600)
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
        elif 'virtualhosts' in filename or 'virtual_hosts' in filename:
            fuzzing_type = "Virtual Host"
            processed_results = results_data.get('virtual_hosts', [])
        else:
            fuzzing_type = "Unknown"
            processed_results = []

        # Calculate status summary
        def get_status(result):
            """Helper to get status from either status or status_code"""
            if isinstance(result.get('status_code'), int):
                return result.get('status_code')
            return result.get('status', 0)
            
        status_2xx = sum(1 for r in processed_results if 200 <= get_status(r) < 300)
        status_3xx = sum(1 for r in processed_results if 300 <= get_status(r) < 400)
        status_4xx = sum(1 for r in processed_results if 400 <= get_status(r) < 500)
        status_5xx = sum(1 for r in processed_results if 500 <= get_status(r) < 600)

        # Get target URL from meta if available
        target_url = results_data.get('meta', {}).get('target_url', '')
        print(f"Processed Results: {processed_results}")

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
# Routes
# These routes are already defined above


if __name__ == '__main__':
    app.run(debug=True)

