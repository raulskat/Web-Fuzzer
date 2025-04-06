#!/usr/bin/env python3
import json
import sys
import requests
import time
from datetime import datetime

def update_results(json_file_path):
    """
    Load JSON file, make HTTP requests to each URL in 'directories' list,
    update with status codes and other information, and save back to file.
    
    Args:
        json_file_path (str): Path to the JSON file to update
    """
    print(f"Loading JSON file: {json_file_path}")
    
    try:
        # Load the JSON file
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        
        # Check if data has the expected structure
        if 'directories' not in data:
            print("Error: JSON file does not contain 'directories' key")
            return
        
        # Keep track of updated URLs
        updated_count = 0
        total_urls = len(data['directories'])
        
        print(f"Found {total_urls} URLs to process")
        
        # Process each URL in the directories list
        for i, url in enumerate(data['directories']):
            print(f"Processing {i+1}/{total_urls}: {url}")
            
            # Make HTTP request with timeout
            try:
                start_time = time.time()
                response = requests.get(url, timeout=5)
                end_time = time.time()
                
                # Calculate response time in milliseconds
                response_time = int((end_time - start_time) * 1000)
                
                # Get content size in bytes
                content_size = len(response.content)
                
                # Get content type
                content_type = response.headers.get('Content-Type', 'N/A')
                if ';' in content_type:
                    content_type = content_type.split(';')[0]
                
                # Convert the simple URL string to a dictionary with details
                data['directories'][i] = {
                    'url': url,
                    'status': response.status_code,
                    'size': content_size,
                    'response_time': response_time,
                    'content_type': content_type,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                updated_count += 1
                
            except requests.exceptions.RequestException as e:
                # Handle request errors by keeping the URL but adding error information
                data['directories'][i] = {
                    'url': url,
                    'status': 'Error',
                    'size': 0,
                    'response_time': 0,
                    'content_type': 'N/A',
                    'error': str(e),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                print(f"  Error: {e}")
        
        # Add timestamp for the update
        data['meta']['updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Save the updated JSON back to the file
        with open(json_file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Successfully updated {updated_count} of {total_urls} URLs")
        print(f"Updated JSON saved to {json_file_path}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Check if file path is provided as command line argument
    if len(sys.argv) < 2:
        print("Usage: python update_results.py <json_file_path>")
        sys.exit(1)
    
    # Get file path from command line arguments
    json_file_path = sys.argv[1]
    
    # Update the results
    update_results(json_file_path)

