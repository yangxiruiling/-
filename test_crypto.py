#!/usr/bin/env python3
"""
Test script for D-H and RSA implementations

This script runs automated tests to verify that all components work correctly.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from diffie_hellman import DiffieHellman
from rsa import RSA


def test_diffie_hellman():
    """Test Diffie-Hellman implementation."""
    print("\n" + "="*60)
    print("Testing Diffie-Hellman Implementation")
    print("="*60)
    
    try:
        # Test basic key exchange
        print("\n1. Testing basic key exchange...")
        alice = DiffieHellman()
        bob = DiffieHellman()
        
        p, g = alice.get_parameters()
        bob.prime = p
        bob.generator = g
        
        alice.generate_private_key()
        alice_public = alice.generate_public_key()
        
        bob.generate_private_key()
        bob_public = bob.generate_public_key()
        
        alice_shared = alice.compute_shared_secret(bob_public)
        bob_shared = bob.compute_shared_secret(alice_public)
        
        assert alice_shared == bob_shared, "Shared secrets don't match!"
        print("   ✓ Shared secrets match")
        
        # Test key derivation
        print("\n2. Testing key derivation...")
        alice_key = alice.derive_key()
        bob_key = bob.derive_key()
        
        assert alice_key == bob_key, "Derived keys don't match!"
        assert len(alice_key) == 32, "Key length incorrect"
        print("   ✓ Key derivation works")
        
        # Test public key validation
        print("\n3. Testing public key validation...")
        assert not alice._validate_public_key(0), "Failed to reject 0"
        assert not alice._validate_public_key(1), "Failed to reject 1"
        assert not alice._validate_public_key(p), "Failed to reject p"
        print("   ✓ Public key validation works")
        
        print("\n✓ All Diffie-Hellman tests passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Diffie-Hellman test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_rsa():
    """Test RSA implementation."""
    print("\n" + "="*60)
    print("Testing RSA Implementation")
    print("="*60)
    
    try:
        # Test key generation
        print("\n1. Testing key generation...")
        rsa = RSA(key_size=512)  # Small for speed
        pub, priv = rsa.generate_keys()
        
        assert pub is not None, "Public key not generated"
        assert priv is not None, "Private key not generated"
        assert pub[1] == priv[1], "Modulus mismatch"
        print("   ✓ Key generation works")
        
        # Test encryption/decryption with integer
        print("\n2. Testing encryption/decryption (integer)...")
        message = 12345
        ciphertext = rsa.encrypt(message)
        plaintext = rsa.decrypt(ciphertext)
        
        assert plaintext == message, f"Decryption failed: {plaintext} != {message}"
        print("   ✓ Encryption/decryption works for integers")
        
        # Test encryption/decryption with string
        print("\n3. Testing encryption/decryption (string)...")
        message_str = "Hello, RSA!"
        ciphertext = rsa.encrypt(message_str)
        plaintext = rsa.decrypt(ciphertext)
        plaintext_str = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big').decode()
        
        assert plaintext_str == message_str, f"String decryption failed"
        print("   ✓ Encryption/decryption works for strings")
        
        # Test digital signatures
        print("\n4. Testing digital signatures...")
        message = "Important message"
        signature = rsa.sign(message)
        verified = rsa.verify(message, signature)
        
        assert verified, "Signature verification failed"
        print("   ✓ Signature creation and verification work")
        
        # Test signature tamper detection
        print("\n5. Testing signature tamper detection...")
        tampered = "Tampered message"
        tampered_verified = rsa.verify(tampered, signature)
        
        assert not tampered_verified, "Failed to detect tampered message"
        print("   ✓ Tamper detection works")
        
        # Test padding makes encryption non-deterministic
        print("\n6. Testing padding (non-deterministic encryption)...")
        msg = 42
        c1 = rsa.encrypt(msg)
        c2 = rsa.encrypt(msg)
        
        assert c1 != c2, "Encryption is deterministic (padding issue)"
        assert rsa.decrypt(c1) == msg, "First ciphertext decryption failed"
        assert rsa.decrypt(c2) == msg, "Second ciphertext decryption failed"
        print("   ✓ Padding makes encryption non-deterministic")
        
        print("\n✓ All RSA tests passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ RSA test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_integration():
    """Test integration between D-H and RSA (authenticated key exchange)."""
    print("\n" + "="*60)
    print("Testing Integration (Authenticated DH with RSA)")
    print("="*60)
    
    try:
        # Alice and Bob have RSA keys for authentication
        print("\n1. Setting up RSA authentication keys...")
        alice_rsa = RSA(key_size=512)
        alice_rsa.generate_keys()
        alice_auth_pub = alice_rsa.get_public_key()
        
        bob_rsa = RSA(key_size=512)
        bob_rsa.generate_keys()
        bob_auth_pub = bob_rsa.get_public_key()
        print("   ✓ Authentication keys generated")
        
        # Perform authenticated D-H exchange
        print("\n2. Performing authenticated D-H exchange...")
        alice_dh = DiffieHellman()
        bob_dh = DiffieHellman()
        
        p, g = alice_dh.get_parameters()
        bob_dh.prime = p
        bob_dh.generator = g
        
        alice_dh.generate_private_key()
        alice_dh_pub = alice_dh.generate_public_key()
        
        bob_dh.generate_private_key()
        bob_dh_pub = bob_dh.generate_public_key()
        
        # Sign D-H public keys
        alice_sig = alice_rsa.sign(str(alice_dh_pub).encode())
        bob_sig = bob_rsa.sign(str(bob_dh_pub).encode())
        print("   ✓ D-H public keys signed")
        
        # Verify signatures
        print("\n3. Verifying signatures...")
        alice_verified = bob_rsa.verify(str(alice_dh_pub).encode(), alice_sig, alice_auth_pub)
        bob_verified = alice_rsa.verify(str(bob_dh_pub).encode(), bob_sig, bob_auth_pub)
        
        assert alice_verified, "Alice's signature verification failed"
        assert bob_verified, "Bob's signature verification failed"
        print("   ✓ Signatures verified")
        
        # Compute shared secrets
        print("\n4. Computing shared secrets...")
        alice_shared = alice_dh.compute_shared_secret(bob_dh_pub)
        bob_shared = bob_dh.compute_shared_secret(alice_dh_pub)
        
        assert alice_shared == bob_shared, "Shared secrets don't match"
        print("   ✓ Shared secrets match")
        
        print("\n✓ Integration test passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("AUTOMATED TEST SUITE FOR D-H AND RSA")
    print("="*60)
    
    results = []
    
    # Run tests
    results.append(("Diffie-Hellman", test_diffie_hellman()))
    results.append(("RSA", test_rsa()))
    results.append(("Integration", test_integration()))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name:20s}: {status}")
        if not passed:
            all_passed = False
    
    print("="*60)
    
    if all_passed:
        print("\n✓ All tests passed successfully!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
