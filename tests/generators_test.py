import pytest
import re
from sgid_client.generators import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)
from tests.mocks.constants import MOCK_CONSTANTS
from tests.mocks.helpers import sha256_b64url

verifier_challenge_pattern = "^[A-Za-z\\d\\-._~]{43,128}$"


class TestGenerateCodeVerifier:
    def test_length_check(self):
        for l in [-1, 0, 42, 129, 138, 999]:
            with pytest.raises(
                Exception,
                match="Code verifier should have a minimum length of 43 and a maximum length of 128",
            ):
                generate_code_verifier(length=l)

    def test_length_default(self):
        verifier = generate_code_verifier()
        assert len(verifier) == 43
        assert re.fullmatch(verifier_challenge_pattern, verifier) is not None

    def test_all_lengths(self):
        for l in range(43, 129):
            verifier = generate_code_verifier(length=l)
            assert len(verifier) == l
            assert re.fullmatch(verifier_challenge_pattern, verifier) is not None


class TestGenerateCodeChallenge:
    def test_hash_correctness(self):
        challenge = generate_code_challenge(MOCK_CONSTANTS.data["code_verifier"])

        assert re.fullmatch(verifier_challenge_pattern, challenge) is not None
        assert challenge == MOCK_CONSTANTS.data["code_challenge"]

    def test_determinism(self):
        challenge_1 = generate_code_challenge(MOCK_CONSTANTS.data["code_verifier"])
        challenge_2 = generate_code_challenge(MOCK_CONSTANTS.data["code_verifier"])

        assert challenge_1 == MOCK_CONSTANTS.data["code_challenge"]
        assert challenge_2 == MOCK_CONSTANTS.data["code_challenge"]


class TestGeneratePkcePair:
    def test_length_check(self):
        for l in [-1, 0, 42, 129, 138, 999]:
            with pytest.raises(
                Exception,
                match="generate_pkce_pair should receive a minimum length of 43 and a maximum length of 128",
            ):
                generate_pkce_pair(length=l)

    def test_length_default(self):
        code_verifier, code_challenge = generate_pkce_pair()
        expected_challenge = sha256_b64url(code_verifier)

        assert len(code_verifier) == 43
        assert re.fullmatch(verifier_challenge_pattern, code_verifier) is not None
        assert re.fullmatch(verifier_challenge_pattern, code_challenge) is not None
        assert code_challenge == expected_challenge

    def test_all_lengths(self):
        for l in range(43, 129):
            code_verifier, code_challenge = generate_pkce_pair(length=l)
            expected_challenge = sha256_b64url(code_verifier)
            assert len(code_verifier) == l
            assert re.fullmatch(verifier_challenge_pattern, code_verifier) is not None
            assert re.fullmatch(verifier_challenge_pattern, code_challenge) is not None
            assert code_challenge == expected_challenge
