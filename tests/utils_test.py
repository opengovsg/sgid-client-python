import pytest
import json
from sgid_client.util import (
    is_stringified_array_or_object,
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
        assert is_stringified_array_or_object(exampleStringifiedArray) == True
        assert is_stringified_array_or_object(corruptedStringifiedArray) == True

    def test_correct_rejection_of_input(self):
        assert is_stringified_array_or_object(exampleStringifiedObject) == False
        assert is_stringified_array_or_object(exampleString) == False

class TestSafeJsonParse:
    def test_correct_parsing_of_json(self):
        assert safe_json_parse(exampleStringifiedArray) == exampleArray
        assert safe_json_parse(exampleStringifiedObject) == exampleObject
    
    def test_return_original_json_string_for_invalid_json(self):
        assert safe_json_parse(corruptedStringifiedArray) == corruptedStringifiedArray
        assert safe_json_parse(exampleString) == exampleString