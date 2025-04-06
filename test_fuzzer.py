import os
import sys
import time
import json
from pathlib import Path

# Add the project root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.fuzzing.directories import DirectoryFuzzer
from src.utils.report_generator import ReportGenerator
from src.utils.config_loader import load_config

def test_directory_fuzzer():
    """
    Comprehensive test for the DirectoryFuzzer class.
    
    This test:
    1. Runs the DirectoryFuzzer against httpbin.org with a variety of paths
    2. Verifies URLs are returned in the expected format
    3. Checks that both default and custom report files are created
    4. Prints detailed debugging information about the results
    
    Returns:
        list: The results from the directory fuzzing operation
    """
    print("Starting DirectoryFuzzer test...")
    
    # Create a more comprehensive test wordlist
    test_wordlist = [
        "admin", "images", "login", "api", "docs", 
        "css", "js", "config", "static", "assets",
        "upload", "data", "test", "about", "user", 
        "health", "status", "ping", "robots.txt", "sitemap.xml"
    ]
    print(f"Using test wordlist with {len(test_wordlist)} entries")
    
    # Test URL - use a public website that can handle a few requests
    test_url = "https://httpbin.org"
    print(f"Using test URL: {test_url}")
    
    # Create a custom report file name for this test
    timestamp = int(time.time())
    report_file = f"test_fuzzing_results_{timestamp}.json"
    
    try:
        # Initialize DirectoryFuzzer with small thread count and longer delay to be nice
        fuzzer = DirectoryFuzzer(
            base_url=test_url,
            wordlist=test_wordlist,
            threads=2,
            delay=1.0
        )
        
        # Monkey patch the generate_wordlist_with_ai method to avoid API calls
        def mock_generate_wordlist(*args, **kwargs):
            print("Using mock AI wordlist generation")
            return ["test", "images", "css", "js"]
        
        # Replace the AI wordlist generation with our mock function
        fuzzer.generate_wordlist_with_ai = mock_generate_wordlist
        
        # Ensure directories fuzzing is enabled in the config
        # This is a bit of a hack but necessary for the test
        config = load_config()
        if not config.get('directories', {}).get('enabled', False):
            print("Temporarily enabling directory fuzzing in config")
            if 'directories' not in config:
                config['directories'] = {}
            config['directories']['enabled'] = True
        
        # Run the directory fuzzing
        print("Running directory fuzzing...")
        start_time = time.time()
        results = fuzzer.fuzz_directories()
        end_time = time.time()
        
        print(f"Fuzzing completed in {end_time - start_time:.2f} seconds. Found {len(results)} results.")
        
        # Save results using the DirectoryFuzzer's report_gen instance with our custom file
        print(f"Using fuzzer's ReportGenerator to save results to {report_file}")
        fuzzer.report_gen.save_report(report_file)
        
        # Verify that results are valid URLs
        valid_urls = [url for url in results if url.startswith(test_url)]
        print(f"Valid URLs found: {len(valid_urls)} out of {len(results)} results")
        
        # Debug output: Print the actual results returned by the fuzzer
        print("\nDEBUG - Raw results from fuzzer:")
        status_counts = {"200": 0, "403": 0, "404": 0, "301": 0, "302": 0, "other": 0}
        
        for i, result in enumerate(results[:10]):  # Show first 10 results to avoid overwhelming output
            if isinstance(result, dict):
                # New format with detailed information
                status = result.get("status", "unknown")
                url = result.get("url", "unknown")
                content_type = result.get("content_type", "unknown")
                size = result.get("size", "unknown")
                response_time = result.get("response_time", "unknown")
                
                print(f"  Result {i+1}: {url} (Status: {status}, Type: {content_type}, Size: {size}, Time: {response_time}ms)")
                
                # Count status codes for statistics
                if status in status_counts:
                    status_counts[str(status)] += 1
                else:
                    status_counts["other"] += 1
            else:
                # Old format with just URLs
                print(f"  Result {i+1}: {result}")
        
        if len(results) > 10:
            print(f"  ... and {len(results) - 10} more results")
            
        # Print status code statistics
        print("\nStatus code distribution:")
        for status, count in status_counts.items():
            print(f"  {status}: {count} results")
        
        # Look for the fuzzing_results.json file that might have been created
        default_report_path = Path("fuzzing_results.json")
        if default_report_path.exists():
            print(f"\nFOUND: fuzzing_results.json was created at: {default_report_path.absolute()}")
            file_size = default_report_path.stat().st_size
            print(f"Report file size: {file_size} bytes")
            
            if file_size == 0:
                print("WARNING: Report file is empty!")
            
            # Read and display the contents of the fuzzing_results.json file
            try:
                with open(default_report_path, 'r') as f:
                    json_data = json.load(f)
                    print("\nDEBUG - Contents of fuzzing_results.json:")
                    print(f"  File structure: {type(json_data)}")
                    
                    if isinstance(json_data, list):
                        print(f"  Number of items: {len(json_data)}")
                        if json_data and len(json_data) > 0:
                            print(f"  First item: {json_data[0]}")
                    elif isinstance(json_data, dict):
                        print(f"  Keys: {list(json_data.keys())}")
                        for key in json_data:
                            value = json_data[key]
                            print(f"  {key}: {type(value)} with {len(value) if hasattr(value, '__len__') else 'N/A'} items")
            except Exception as e:
                print(f"Error reading fuzzing_results.json: {e}")
        else:
            print(f"\nNOT FOUND: fuzzing_results.json was not created at: {default_report_path.absolute()}")
            
        # Also still check our custom report file
        report_path = Path(report_file)
        if report_path.exists():
            print(f"\nSUCCESS: Custom report file was created at: {report_path.absolute()}")
            file_size = report_path.stat().st_size
            print(f"Report file size: {file_size} bytes")
            
            if file_size == 0:
                print("WARNING: Custom report file is empty!")
            else:
                # Read and display the contents of the custom report file
                try:
                    with open(report_path, 'r') as f:
                        json_data = json.load(f)
                        print("\nDEBUG - Contents of custom report file:")
                        print(f"  File structure: {type(json_data)}")
                        
                        if isinstance(json_data, list):
                            print(f"  Number of items: {len(json_data)}")
                            if json_data and len(json_data) > 0:
                                print(f"  First item: {json_data[0]}")
                        elif isinstance(json_data, dict):
                            print(f"  Keys: {list(json_data.keys())}")
                            for key in json_data:
                                value = json_data[key]
                                print(f"  {key}: {type(value)} with {len(value) if hasattr(value, '__len__') else 'N/A'} items")
                except Exception as e:
                    print(f"Error reading custom report file: {e}")
        else:
            print(f"\nERROR: Custom report file was not created at: {report_path.absolute()}")
            print("This suggests that the ReportGenerator save_report() method with custom path is not working correctly.")
    except Exception as e:
        print(f"ERROR: Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return []
        
    # Return the results for verification
    return results
def verify_test_results(results, default_report_exists, custom_report_exists):
    """Verify if the test was successful based on multiple criteria."""
    success = True
    print("\n=== TEST SUMMARY ===")
    
    # Check if we got any results
    if not results or len(results) == 0:
        print("❌ FAILED: No directory fuzzing results were returned")
        success = False
    else:
        print(f"✅ PASSED: Got {len(results)} results from directory fuzzing")
        
    # Check if the DirectoryFuzzer's ReportGenerator was used correctly
    if not custom_report_exists:
        print("❌ FAILED: DirectoryFuzzer's ReportGenerator wasn't used correctly")
        success = False
    else:
        print("✅ PASSED: DirectoryFuzzer's ReportGenerator was used correctly")
    # Check if default report was created
    if not default_report_exists:
        print("❌ FAILED: Default report file (fuzzing_results.json) was not created")
        success = False
    else:
        print("✅ PASSED: Default report file was created")
    
    # Check if custom report was created
    if not custom_report_exists:
        print("❌ FAILED: Custom report file was not created")
        success = False
    else:
        print("✅ PASSED: Custom report file was created")
    
    # Final result
    if success:
        print("\nOVERALL RESULT: All tests PASSED! 🎉")
    else:
        print("\nOVERALL RESULT: Some tests FAILED. 😥")
    
    return success

if __name__ == "__main__":
    results = test_directory_fuzzer()
    
    # Check if both report files exist
    default_report_exists = Path("fuzzing_results.json").exists()
    custom_report_exists = any(Path().glob("test_fuzzing_results_*.json"))
    
    # Verify the test results
    success = verify_test_results(results, default_report_exists, custom_report_exists)
    
    # Return a non-zero exit code if the test failed
    if not success:
        sys.exit(1)

