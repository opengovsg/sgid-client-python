import pytest
import json
from urllib.parse import urlparse, parse_qs
from .mocks.constants import MOCK_CONSTANTS
from .mocks.helpers import (
    get_client,
)
from sgid_client.error import Errors


class TestParseData:
    def test_parse_valid_object(self):
        # Arrange
        client = get_client()

        # Act
        stringifiedChildRecords = '[{"nric":"T1872646C","name":"LIM YONG JIN","date_of_birth":"2018-05-05","sex":"MALE","race":"MALAY","life_status":"ALIVE","nationality":"BRITISH OVERSEAS TERRITORIES CITIZEN","residential_status":"PR"}]'
        inputData = {
            'myinfo.name': 'Kwa Jie Hao',
            'myinfo.sponsored_child_records': stringifiedChildRecords,
        }
        parsedData = client.parseData(inputData)

        # Assert
        expectedData = {
            'myinfo.name': 'Kwa Jie Hao',
            'myinfo.sponsored_child_records': json.loads(stringifiedChildRecords),
        }
        assert (parsedData == expectedData)

    # It should do nothing if there are no stringified arrays or objects in the input data object
    def test_parse_valid_object_do_nothing(self):
        # Arrange
        client = get_client()

        # Act
        testDict = {'a': 'test'}
        parsedData = client.parseData(testDict)

        # Assert
        assert (parsedData == testDict)

    def test_parse_none_value(self):
        # Arrange
        client = get_client()

        # Act
        with pytest.raises(
            Exception,
            match=Errors.INVALID_SGID_USERINFO_DATA_ERROR,
        ):
            client.parseData(None)

    def test_parse_array_value(self):
        # Arrange
        client = get_client()

        # Act
        with pytest.raises(
            Exception,
            match=Errors.INVALID_SGID_USERINFO_DATA_ERROR,
        ):
            client.parseData(['test'])

    def test_parse_string_value(self):
        # Arrange
        client = get_client()

        # Act
        with pytest.raises(
            Exception,
            match=Errors.INVALID_SGID_USERINFO_DATA_ERROR,
        ):
            client.parseData('test')

    # It should throw an error if the input is an object, but has non-string values
    def test_parse_object_with_non_string_values(self):
        # Arrange
        client = get_client()

        # Act
        with pytest.raises(
            Exception,
            match=Errors.INVALID_SGID_USERINFO_DATA_ERROR,
        ):
            client.parseData({'test': 123})

    # It should throw an error if the input is an object, but has non-string values
    def test_parse_object_with_non_string_keys(self):
        # Arrange
        client = get_client()

        # Act
        with pytest.raises(
            Exception,
            match=Errors.INVALID_SGID_USERINFO_DATA_ERROR,
        ):
            client.parseData({123: 'test'})
