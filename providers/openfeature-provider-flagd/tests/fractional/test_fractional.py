import json
import os
import pytest
from openfeature import api
from openfeature.contrib.provider.flagd import FlagdProvider
from openfeature.contrib.provider.flagd.config import ResolverType
from openfeature.evaluation_context import EvaluationContext
from openfeature.flag_evaluation import Reason

@pytest.fixture(scope="module")
def flagd_provider():
    # Use absolute path for the flag configuration file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(current_dir, "flag_config.json")
    
    provider = FlagdProvider(
        resolver_type=ResolverType.IN_PROCESS,
        offline_flag_source_path=config_path
    )
    api.set_provider(provider)
    yield provider
    provider.shutdown()

def get_test_files():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(current_dir, "test1000")
    json_files = [f for f in os.listdir(test_dir) if f.endswith(".json")]
    json_files.sort(key=lambda x: int(os.path.splitext(x)[0]))
    return [(f, test_dir) for f in json_files]

@pytest.mark.parametrize("filename, test_dir", get_test_files())
def test_fractional_individual(flagd_provider, filename, test_dir):
    client = api.get_client()
    test_id = os.path.splitext(filename)[0]
    file_path = os.path.join(test_dir, filename)
    
    with open(file_path, "r") as f:
        test_input = json.load(f)
    
    # Build evaluation context as requested:
    # json= test input, id= test number, path=test folder path
    context = EvaluationContext(
        targeting_key=str(test_id),
        attributes={
            "json": test_input,
            "id": test_id,
            "path": test_dir
        }
    )
    
    # Execute evaluation for "basic-flag" with details to catch errors
    result_details = client.get_boolean_details("basic-flag", False, context)
    
    # Check for errors during evaluation
    assert result_details.error_code is None, f"Test {test_id} failed with error: {result_details.error_code} - {result_details.error_message}"
    assert result_details.reason == Reason.TARGETING_MATCH, f"Test {test_id} failed: expected reason TARGETING_MATCH, got {result_details.reason}"
    
    # Verify that the result is a boolean
    assert isinstance(result_details.value, bool), f"Test {test_id} failed: expected boolean result, got {type(result_details.value)}"

if __name__ == "__main__":
    pytest.main([__file__])
