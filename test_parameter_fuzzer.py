import asyncio
import json
import os
import sys

# Add the project root directory to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from src.fuzzing.parameters import ParameterFuzzer

async def test_parameter_fuzzer():
    """Test the ParameterFuzzer class with a sample URL."""
    print("Testing Parameter Fuzzer...")
    
    # URL with query parameters for testing
    test_url = "https://example.com/search?q=test&page=1&sort=desc"
    
    # Initialize the fuzzer
    fuzzer = ParameterFuzzer(
        target_url=test_url,
        async_requests=5,
        timeout=3,
        request_delay=0.1,
        verify_ssl=False  # Set to False for testing purposes
    )
    
    # Run the fuzzer
    print(f"Running parameter fuzzing on {test_url}...")
    results = await fuzzer.run()
    
    # Save the results to a JSON file
    result_file = "test_parameter_results.json"
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Print a summary of the results
    print(f"\nFuzzing completed. Found {len(results)} potential issues.")
    
    if results:
        vulnerable_params = sum(1 for r in results if r.get('score', 0) > 3)
        print(f"Potentially vulnerable parameters: {vulnerable_params}")
        
        # Print top 3 findings
        print("\nTop findings:")
        for i, result in enumerate(results[:3]):
            print(f"{i+1}. Parameter: {result.get('param')}")
            print(f"   Payload: {result.get('payload')}")
            print(f"   Score: {result.get('score')}")
            print(f"   Evidence: {', '.join(result.get('evidence', []))}")
            print()
    
    print(f"Results saved to {result_file}")
    return len(results) > 0

if __name__ == "__main__":
    success = asyncio.run(test_parameter_fuzzer())
    sys.exit(0 if success else 1) 