from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher, OperatorType
from presidio_anonymizer.entities import InvalidParamError

@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size):
    # Mock is_valid_key_size to return False to trigger the error path
    mock_is_valid_key_size.return_value = False
    
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

def test_operator_name():
    """Test that operator_name returns the correct name."""
    operator = Encrypt()
    assert operator.operator_name() == "encrypt"


def test_operator_type():
    """Test that operator_type returns the correct type."""
    operator = Encrypt()
    assert operator.operator_type() == OperatorType.Anonymize

@pytest.mark.parametrize("key", [
    "1234567890123456",           # 128 bits (16 bytes) string
    "123456789012345678901234",   # 192 bits (24 bytes) string
    "12345678901234567890123456789012",  # 256 bits (32 bytes) string
    b"1234567890123456",          # 128 bits (16 bytes) bytes
    b"123456789012345678901234",  # 192 bits (24 bytes) bytes
    b"12345678901234567890123456789012",  # 256 bits (32 bytes) bytes
])
def test_valid_keys(key):
    """Test that validate succeeds for valid key sizes (128, 192, 256 bits)."""
    Encrypt().validate(params={"key": key})