import json
from datetime import datetime
import base64

class ReportGenerator:
    def __init__(self, output_file="fuzzing_results.json"):
        """
        Initialize the report generator with an output file.
        """
        self.output_file = output_file
        self.results = {
            "directories": [],
            "subdomains": [],
            "api_endpoints": [],
            "meta": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tool": "Web Application Fuzzer"
            }
        }

    def add_result(self, category, result):
        """
        Add a result to a specific category (directories, subdomains, or API endpoints).
        Ensures each result has the required fields and proper data types.
        
        Args:
            category (str): The category to add the result to (directories, subdomains, or api_endpoints)
            result (dict): The result to add, containing url, status, size, response_time, content_type, etc.
        """
        if category in self.results:
            # Normalize the result format
            normalized_result = self._normalize_result(result, category)
            if normalized_result:
                self.results[category].append(normalized_result)
            
    def _normalize_result(self, result, category):
        """
        Normalize the result to ensure it has all required fields and valid data types.
        
        Args:
            result (dict): The result to normalize
            category (str): The category of the result
            
        Returns:
            dict: Normalized result with all required fields
        """
        try:
            if not isinstance(result, dict):
                print(f"Error normalizing result: Expected dict but got {type(result).__name__}")
                return None
                
            normalized = {}
            
            # Helper function to safely convert values to int
            def safe_int(value, default=0):
                if value is None:
                    return default
                try:
                    return int(value)
                except (ValueError, TypeError):
                    return default
                    
            # Helper function to safely convert values to string
            def safe_str(value, default=""):
                if value is None:
                    return default
                return str(value)
            
            # Get timestamp with fallback
            timestamp = result.get("timestamp")
            if not timestamp:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if category == "directories":
                # Required fields for directory entries
                normalized = {
                    "url": safe_str(result.get("url"), ""),
                    "status": safe_int(result.get("status"), 404),  # Default to 404 if missing
                    "size": safe_int(result.get("size"), 0),
                    "response_time": safe_int(result.get("response_time"), 0),
                    "content_type": safe_str(result.get("content_type"), "unknown"),
                    "timestamp": timestamp
                }
            elif category == "subdomains":
                # Fields for subdomain entries
                normalized = {
                    "subdomain": safe_str(result.get("subdomain"), ""),
                    "ip": safe_str(result.get("ip"), ""),
                    "status": safe_int(result.get("status"), 0),
                    "timestamp": timestamp
                }
            elif category == "api_endpoints":
                # Fields for API endpoint entries
                normalized = {
                    "url": safe_str(result.get("url"), ""),
                    "method": safe_str(result.get("method"), "GET"),
                    "status": safe_int(result.get("status"), 404),  # Default to 404 if missing
                    "response_time": safe_int(result.get("response_time"), 0),
                    "content_type": safe_str(result.get("content_type"), "unknown"),
                    "timestamp": timestamp
                }
            else:
                print(f"Error normalizing result: Unknown category '{category}'")
                return None
            
            return normalized
        except Exception as e:
            print(f"Error normalizing result for category '{category}': {str(e)}")
            print(f"Original result: {result}")
            return None

    def add_metadata(self, category, metadata):
        """
        Add metadata to the report under a specific category.
        
        Args:
            category (str): The category under which to store metadata
            metadata (dict): The metadata to store
                
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not isinstance(category, str):
                print(f"Error: category must be a string, got {type(category)}")
                return False
                
            if not isinstance(metadata, dict):
                print(f"Error: metadata must be a dictionary, got {type(metadata)}")
                return False
                
            # Initialize meta category if it doesn't exist
            if "meta" not in self.results:
                self.results["meta"] = {}
                
            # Add metadata under the category
            self.results["meta"][category] = metadata
            return True
        except Exception as e:
            print(f"Error adding metadata: {e}")
            return False
            
    def save_report(self, output_path=None):
        """
        Save the consolidated results to the output file in JSON format.
        
        Args:
            output_path (str, optional): Custom output path where the report should be saved.
                                        If not provided, uses the default path (self.output_file).
        """
        file_path = output_path if output_path else self.output_file
        try:
            # Ensure all data is JSON serializable
            serializable_results = self._prepare_for_serialization(self.results)
            
            with open(file_path, "w") as file:
                json.dump(serializable_results, file, indent=4)
            print(f"Results saved to {file_path}")
            return True
        except Exception as e:
            print(f"Error saving report: {e}")
            return False
            
    def _prepare_for_serialization(self, data):
        """
        Recursively prepare data for JSON serialization by handling non-serializable types.
        
        Args:
            data: The data structure to prepare
            
        Returns:
            The data structure with all elements converted to JSON-serializable types
        """
        if isinstance(data, dict):
            return {k: self._prepare_for_serialization(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._prepare_for_serialization(item) for item in data]
        elif isinstance(data, bytes):
            # Convert bytes to base64 string
            try:
                # First try to decode as UTF-8
                return data.decode('utf-8')
            except UnicodeDecodeError:
                # If that fails, encode as base64
                return base64.b64encode(data).decode('ascii')
        elif isinstance(data, (int, float, str, bool, type(None))):
            return data
        else:
            # Convert other types to string
            return str(data)
