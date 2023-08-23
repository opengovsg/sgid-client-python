import pytest
import json
from sgid_client.util import (
    is_string_wrapped_in_square_brackets,
    safe_json_parse
)

exampleArray = ['a', 'b', 'c']
exampleStringifiedArray = json.dumps(exampleArray)
corruptedStringifiedArray = '["a", ]]]]'
exampleObject = { "a": 'b' }
exampleStringifiedObject = json.dumps(exampleObject)
exampleString = 'hello world'

class TestIsStringWrappedInSquareBrackets:
    def test_correct_identification_of_input(self):
        assert is_string_wrapped_in_square_brackets(exampleStringifiedArray) == True
        assert is_string_wrapped_in_square_brackets(corruptedStringifiedArray) == True

    def test_correct_rejection_of_input(self):
        assert is_string_wrapped_in_square_brackets(exampleStringifiedObject) == False
        assert is_string_wrapped_in_square_brackets(exampleString) == False

class TestSafeJsonParse:
    def test_correct_parsing_of_json(self):
        assert safe_json_parse(exampleStringifiedArray) == exampleArray
        assert safe_json_parse(exampleStringifiedObject) == exampleObject
    
    def test_return_original_json_string_for_invalid_json(self):
        assert safe_json_parse(corruptedStringifiedArray) == corruptedStringifiedArray
        assert safe_json_parse(exampleString) == exampleString