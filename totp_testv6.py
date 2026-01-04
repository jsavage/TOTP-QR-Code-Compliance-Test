#!/usr/bin/env python3
"""
TOTP QR Code Compliance Test Suite
Based on RFC 6238 - Time-Based One-Time Password Algorithm

Tests mandatory requirements for 2FA QR code URI encoding and content.

Run this script and the script will enable you to select any image contained in the current folder as input.  
Results will be listed to screen. 

"""

import os
import re
import subprocess
import sys
from typing import Tuple, Optional, List, Dict
from urllib.parse import urlparse, parse_qs, unquote
import base64


# ============================================================================
# MANDATORY REQUIREMENTS TABLE
# ============================================================================

REQUIREMENTS = {
    1: "URI must use the 'otpauth://' scheme",
    2: "URI must specify 'totp' as the OTP type (not hotp or other)",
    3: "URI must contain a label/account identifier after '/totp/'",
    4: "URI must contain a 'secret' parameter",
    5: "Secret parameter must not be empty",
    6: "Secret must contain only valid Base32 characters (A-Z, 2-7, =)",
    7: "Secret must decode to at least 128 bits (16 bytes, 26 Base32 chars minimum)",
    8: "Secret must decode to at least 160 bits (20 bytes) for SHA-1 (RECOMMENDED)",
    9: "If 'algorithm' parameter is present, it must be SHA1, SHA256, or SHA512",
    10: "If 'period' parameter is present, it must be a positive integer",
    11: "If 'digits' parameter is present, it must be a positive integer (typically 6 or 8)",
    12: "URI must NOT contain a 'counter' parameter (counter is for HOTP, not TOTP)",
    13: "Label must be properly percent-encoded (special chars like :, /, ? must be encoded)",
}


# ============================================================================
# TEST RESULT CLASS
# ============================================================================

class TestResult:
    """Stores the result of a single test."""
    
    def __init__(self, req_id: int, passed: bool, evidence: str = ""):
        self.req_id = req_id
        self.passed = passed
        self.evidence = evidence
        self.requirement = REQUIREMENTS[req_id]
    
    def __repr__(self):
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return f"[R{self.req_id:02d}] {status}: {self.requirement}"


# ============================================================================
# QR CODE SCANNER
# ============================================================================

def scan_qr_code(image_path: str) -> Tuple[bool, str]:
    """
    Scan a QR code image using zbarimg.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        Tuple of (success, uri_or_error_message)
    """
    if not os.path.exists(image_path):
        return False, f"File not found: {image_path}"
    
    try:
        result = subprocess.run(
            ['zbarimg', '--quiet', '--raw', image_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return False, "No QR code detected in image or zbarimg error"
        
        uri = result.stdout.strip()
        if not uri:
            return False, "QR code detected but no data extracted"
        
        return True, uri
        
    except FileNotFoundError:
        return False, "zbarimg not found. Please install: sudo apt-get install zbar-tools"
    except subprocess.TimeoutExpired:
        return False, "Timeout while scanning QR code"
    except Exception as e:
        return False, f"Error scanning QR code: {str(e)}"


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_base32(secret: str) -> Tuple[bool, str]:
    """
    Validate that a string contains only valid Base32 characters.
    
    Args:
        secret: The secret string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Base32 alphabet: A-Z (uppercase), 2-7, and optional padding =
    base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
    
    if not base32_pattern.match(secret):
        invalid_chars = set(c for c in secret if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
        return False, f"Invalid characters found: {invalid_chars}"
    
    # Check padding rules: padding can only be at the end
    if '=' in secret:
        padding_start = secret.index('=')
        if any(c != '=' for c in secret[padding_start:]):
            return False, "Invalid padding: non-padding characters after padding character"
    
    return True, ""


def decode_base32_secret(secret: str) -> Tuple[Optional[bytes], str]:
    """
    Attempt to decode a Base32 secret.
    
    Args:
        secret: The Base32-encoded secret
        
    Returns:
        Tuple of (decoded_bytes or None, error_message)
    """
    try:
        # Python's base64 module requires uppercase
        secret_upper = secret.upper()
        decoded = base64.b32decode(secret_upper)
        return decoded, ""
    except Exception as e:
        return None, f"Base32 decode error: {str(e)}"


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_req_01_scheme(uri: str) -> TestResult:
    """R01: URI must use the 'otpauth://' scheme"""
    scheme = uri.split('://')[0] if '://' in uri else ""
    passed = scheme.lower() == 'otpauth'
    evidence = f"Found scheme: '{scheme}'" if scheme else "No scheme found (no '://' in URI)"
    return TestResult(1, passed, evidence)


def test_req_02_type(uri: str) -> TestResult:
    """R02: URI must specify 'totp' as the OTP type"""
    try:
        parsed = urlparse(uri)
        # In otpauth://totp/label, 'totp' is the netloc (network location)
        otp_type = parsed.netloc
        passed = otp_type.lower() == 'totp'
        evidence = f"Found OTP type: '{otp_type}'" if otp_type else "No OTP type found"
        return TestResult(2, passed, evidence)
    except Exception as e:
        return TestResult(2, False, f"Error parsing URI: {str(e)}")


def test_req_03_label(uri: str) -> TestResult:
    """R03: URI must contain a label/account identifier"""
    try:
        parsed = urlparse(uri)
        # In otpauth://totp/label, the label is in the path
        # Remove leading slash and get the label
        label = parsed.path.lstrip('/')
        # Split on '?' to handle any query params that might be in path
        label = label.split('?')[0]
        label = unquote(label)  # URL decode
        passed = len(label) > 0
        evidence = f"Found label: '{label}'" if label else "No label found in path"
        return TestResult(3, passed, evidence)
    except Exception as e:
        return TestResult(3, False, f"Error parsing URI: {str(e)}")


def test_req_04_secret_exists(uri: str) -> TestResult:
    """R04: URI must contain a 'secret' parameter"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        passed = 'secret' in params
        evidence = f"Parameters found: {list(params.keys())}" if params else "No query parameters found"
        return TestResult(4, passed, evidence)
    except Exception as e:
        return TestResult(4, False, f"Error parsing URI: {str(e)}")


def test_req_05_secret_not_empty(uri: str) -> TestResult:
    """R05: Secret parameter must not be empty"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        if 'secret' not in params:
            return TestResult(5, False, "No 'secret' parameter found")
        
        secret = params['secret'][0]
        passed = len(secret) > 0
        evidence = f"Secret length: {len(secret)} characters" if secret else "Secret is empty string"
        return TestResult(5, passed, evidence)
    except Exception as e:
        return TestResult(5, False, f"Error parsing URI: {str(e)}")


def test_req_06_secret_base32(uri: str) -> TestResult:
    """R06: Secret must contain only valid Base32 characters"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        if 'secret' not in params:
            return TestResult(6, False, "No 'secret' parameter found")
        
        secret = params['secret'][0]
        is_valid, error = validate_base32(secret)
        evidence = f"Secret: '{secret}' - {error}" if not is_valid else f"Secret: '{secret}' (valid Base32)"
        return TestResult(6, is_valid, evidence)
    except Exception as e:
        return TestResult(6, False, f"Error parsing URI: {str(e)}")


def test_req_07_secret_min_128bit(uri: str) -> TestResult:
    """R07: Secret must decode to at least 128 bits (16 bytes)"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        if 'secret' not in params:
            return TestResult(7, False, "No 'secret' parameter found")
        
        secret = params['secret'][0]
        decoded, error = decode_base32_secret(secret)
        
        if decoded is None:
            return TestResult(7, False, f"Cannot decode secret: {error}")
        
        byte_length = len(decoded)
        bit_length = byte_length * 8
        passed = byte_length >= 16
        evidence = f"Secret decodes to {byte_length} bytes ({bit_length} bits). Minimum: 16 bytes (128 bits)"
        return TestResult(7, passed, evidence)
    except Exception as e:
        return TestResult(7, False, f"Error: {str(e)}")


def test_req_08_secret_recommended_160bit(uri: str) -> TestResult:
    """R08: Secret should decode to at least 160 bits (20 bytes) for SHA-1"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        if 'secret' not in params:
            return TestResult(8, False, "No 'secret' parameter found")
        
        secret = params['secret'][0]
        decoded, error = decode_base32_secret(secret)
        
        if decoded is None:
            return TestResult(8, False, f"Cannot decode secret: {error}")
        
        byte_length = len(decoded)
        bit_length = byte_length * 8
        passed = byte_length >= 20
        evidence = f"Secret decodes to {byte_length} bytes ({bit_length} bits). Recommended: 20 bytes (160 bits) for SHA-1"
        return TestResult(8, passed, evidence)
    except Exception as e:
        return TestResult(8, False, f"Error: {str(e)}")


def test_req_09_algorithm_valid(uri: str) -> TestResult:
    """R09: If 'algorithm' parameter exists, it must be SHA1, SHA256, or SHA512"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        if 'algorithm' not in params:
            return TestResult(9, True, "No 'algorithm' parameter (optional, default SHA1)")
        
        algorithm = params['algorithm'][0].upper()
        valid_algorithms = ['SHA1', 'SHA256', 'SHA512']
        passed = algorithm in valid_algorithms
        evidence = f"Found algorithm: '{algorithm}'. Valid: {valid_algorithms}"
        return TestResult(9, passed, evidence)
    except Exception as e:
        return TestResult(9, False, f"Error parsing URI: {str(e)}")


def test_req_10_period_valid(uri: str) -> TestResult:
    """R10: If 'period' parameter exists, it must be a positive integer"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        if 'period' not in params:
            return TestResult(10, True, "No 'period' parameter (optional, default 30)")
        
        period_str = params['period'][0]
        try:
            period = int(period_str)
            passed = period > 0
            evidence = f"Found period: {period}. Must be positive integer."
            return TestResult(10, passed, evidence)
        except ValueError:
            return TestResult(10, False, f"Period '{period_str}' is not a valid integer")
    except Exception as e:
        return TestResult(10, False, f"Error parsing URI: {str(e)}")


def test_req_11_digits_valid(uri: str) -> TestResult:
    """R11: If 'digits' parameter exists, it must be a positive integer"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        if 'digits' not in params:
            return TestResult(11, True, "No 'digits' parameter (optional, default 6)")
        
        digits_str = params['digits'][0]
        try:
            digits = int(digits_str)
            passed = digits > 0
            evidence = f"Found digits: {digits}. Must be positive integer (typically 6 or 8)."
            return TestResult(11, passed, evidence)
        except ValueError:
            return TestResult(11, False, f"Digits '{digits_str}' is not a valid integer")
    except Exception as e:
        return TestResult(11, False, f"Error parsing URI: {str(e)}")


def test_req_12_no_counter(uri: str) -> TestResult:
    """R12: URI must NOT contain a 'counter' parameter (HOTP only)"""
    try:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        has_counter = 'counter' in params
        passed = not has_counter
        evidence = "Found 'counter' parameter (this indicates HOTP, not TOTP)" if has_counter else "No 'counter' parameter found (correct for TOTP)"
        return TestResult(12, passed, evidence)
    except Exception as e:
        return TestResult(12, False, f"Error parsing URI: {str(e)}")


def test_req_13_label_encoding(uri: str) -> TestResult:
    """R13: Label must be properly percent-encoded"""
    try:
        # Parse the raw URI to get the label before any decoding
        parsed = urlparse(uri)
        # Get the raw path (label)
        raw_label = parsed.path.lstrip('/')
        raw_label = raw_label.split('?')[0]
        
        # Characters that MUST be percent-encoded in URI path components (RFC 3986)
        # These are reserved characters with special meaning in URIs
        problematic_chars = {
            ':': '%3A',
            '/': '%2F',
            '?': '%3F',
            '#': '%23',
            '[': '%5B',
            ']': '%5D',
            '@': '%40',
        }
        
        # Check for unencoded special characters
        found_unencoded = []
        for char, encoded in problematic_chars.items():
            if char in raw_label and encoded not in raw_label:
                found_unencoded.append(f"'{char}' (should be {encoded})")
        
        passed = len(found_unencoded) == 0
        
        if passed:
            evidence = f"Label '{raw_label}' is properly encoded"
        else:
            evidence = f"Label '{raw_label}' contains unencoded characters: {', '.join(found_unencoded)}"
        
        return TestResult(13, passed, evidence)
    except Exception as e:
        return TestResult(13, False, f"Error parsing URI: {str(e)}")


# ============================================================================
# TEST SUITE RUNNER
# ============================================================================

def run_all_tests(uri: str) -> List[TestResult]:
    """Run all validation tests on a URI."""
    tests = [
        test_req_01_scheme,
        test_req_02_type,
        test_req_03_label,
        test_req_04_secret_exists,
        test_req_05_secret_not_empty,
        test_req_06_secret_base32,
        test_req_07_secret_min_128bit,
        test_req_08_secret_recommended_160bit,
        test_req_09_algorithm_valid,
        test_req_10_period_valid,
        test_req_11_digits_valid,
        test_req_12_no_counter,
        test_req_13_label_encoding,
    ]
    
    results = []
    for test_func in tests:
        result = test_func(uri)
        results.append(result)
    
    return results


def print_results(results: List[TestResult], uri: str):
    """Print test results in a formatted way."""
    print("\n" + "="*80)
    print("TOTP QR CODE COMPLIANCE TEST RESULTS")
    print("="*80)
    print(f"\nDecoded URI:\n{uri}\n")
    print("-"*80)
    
    passed_count = sum(1 for r in results if r.passed)
    total_count = len(results)
    
    # Print failed tests first (if any)
    failed_tests = [r for r in results if not r.passed]
    if failed_tests:
        print("\n❌ FAILED TESTS:\n")
        for result in failed_tests:
            print(f"{result}")
            print(f"   Requirement: {result.requirement}")
            print(f"   Evidence: {result.evidence}")
            print()
    
    # Print passed tests
    passed_tests = [r for r in results if r.passed]
    if passed_tests:
        print("\n✓ PASSED TESTS:\n")
        for result in passed_tests:
            print(f"{result}")
            if result.evidence and "optional" not in result.evidence.lower():
                print(f"   Evidence: {result.evidence}")
        print()
    
    # Summary
    print("-"*80)
    print(f"\nSUMMARY: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n✓ QR CODE IS COMPLIANT with RFC 6238 mandatory requirements")
    else:
        print(f"\n✗ QR CODE IS NON-COMPLIANT ({total_count - passed_count} requirement(s) failed)")
    
    print("="*80 + "\n")


# ============================================================================
# FILE SELECTION
# ============================================================================

def list_image_files() -> List[str]:
    """List all PNG and JPG files in the current directory."""
    files = []
    for filename in os.listdir('.'):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            files.append(filename)
    return sorted(files)


def select_image_file() -> Optional[str]:
    """Interactive file selection."""
    files = list_image_files()
    
    if not files:
        print("No PNG or JPG files found in current directory.")
        return None
    
    print("\n" + "="*80)
    print("TOTP QR CODE IMAGE FILES")
    print("="*80)
    for i, filename in enumerate(files, 1):
        file_size = os.path.getsize(filename)
        print(f"{i:2d}. {filename} ({file_size:,} bytes)")
    
    print("\nEnter the number of the file to test (or 'q' to quit): ", end='')
    
    try:
        choice = input().strip()
        if choice.lower() == 'q':
            return None
        
        index = int(choice) - 1
        if 0 <= index < len(files):
            return files[index]
        else:
            print(f"Invalid selection. Please enter a number between 1 and {len(files)}")
            return None
    except (ValueError, KeyboardInterrupt):
        return None


# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    """Main program entry point."""
    print("\n" + "="*80)
    print("TOTP QR CODE COMPLIANCE TEST SUITE")
    print("Based on RFC 6238 - Time-Based One-Time Password Algorithm")
    print("="*80)
    
    # Select image file
    image_file = select_image_file()
    if not image_file:
        print("\nExiting.")
        return 1
    
    print(f"\nScanning QR code from: {image_file}")
    
    # Scan QR code
    success, uri_or_error = scan_qr_code(image_file)
    
    if not success:
        print(f"\n❌ ERROR: {uri_or_error}\n")
        return 1
    
    # Run tests
    results = run_all_tests(uri_or_error)
    
    # Print results
    print_results(results, uri_or_error)
    
    # Return exit code based on results
    all_passed = all(r.passed for r in results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
