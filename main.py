"""
Main demonstration script for D-H and RSA implementations

This script demonstrates the object-oriented implementations of:
1. Diffie-Hellman key exchange
2. RSA encryption/decryption
3. Various attacks on both algorithms
4. Defense mechanisms against these attacks
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from diffie_hellman import DiffieHellman
from rsa import RSA
from dh_attacks import demonstrate_dh_attacks_and_defenses
from rsa_attacks import demonstrate_rsa_attacks_and_defenses


def demonstrate_dh_basic():
    """
    Demonstrate basic Diffie-Hellman key exchange.
    """
    print("\n" + "=" * 70)
    print(" " * 15 + "BASIC DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 70)
    
    print("\nScenario: Alice and Bob want to establish a shared secret key")
    print("over an insecure channel.\n")
    
    # Alice creates her D-H instance
    print("1. Alice initializes D-H with parameters (p, g)")
    alice = DiffieHellman()
    p, g = alice.get_parameters()
    print(f"   Parameters: p (prime) has {p.bit_length()} bits, g (generator) = {g}")
    
    # Bob creates his D-H instance with same parameters
    print("\n2. Bob uses the same parameters")
    bob = DiffieHellman()
    bob.prime = p
    bob.generator = g
    
    # Alice generates her private and public keys
    print("\n3. Alice generates her private key (secret)")
    alice.generate_private_key()
    print("   Alice's private key: [HIDDEN]")
    
    print("\n4. Alice computes her public key: A = g^a mod p")
    alice_public = alice.generate_public_key()
    print(f"   Alice's public key: {alice_public}")
    
    # Bob generates his private and public keys
    print("\n5. Bob generates his private key (secret)")
    bob.generate_private_key()
    print("   Bob's private key: [HIDDEN]")
    
    print("\n6. Bob computes his public key: B = g^b mod p")
    bob_public = bob.generate_public_key()
    print(f"   Bob's public key: {bob_public}")
    
    # Exchange public keys (can be done over insecure channel)
    print("\n7. Alice and Bob exchange public keys over insecure channel")
    
    # Compute shared secrets
    print("\n8. Alice computes shared secret: s = B^a mod p")
    alice_shared = alice.compute_shared_secret(bob_public)
    
    print("\n9. Bob computes shared secret: s = A^b mod p")
    bob_shared = bob.compute_shared_secret(alice_public)
    
    # Verify they match
    print(f"\n10. Shared secrets match: {alice_shared == bob_shared}")
    
    # Derive encryption key
    alice_key = alice.derive_key()
    bob_key = bob.derive_key()
    
    print(f"\n11. Derived encryption keys match: {alice_key == bob_key}")
    print(f"    Key (hex): {alice_key.hex()}")
    
    print("\n" + "=" * 70)
    print("Alice and Bob now have a shared secret key!")
    print("=" * 70)


def demonstrate_rsa_basic():
    """
    Demonstrate basic RSA encryption and decryption.
    """
    print("\n" + "=" * 70)
    print(" " * 20 + "BASIC RSA ENCRYPTION/DECRYPTION")
    print("=" * 70)
    
    print("\nScenario: Alice wants to send an encrypted message to Bob.\n")
    
    # Bob generates RSA keys
    print("1. Bob generates RSA key pair")
    bob_rsa = RSA(key_size=1024)  # Smaller for demo speed
    bob_rsa.generate_keys()
    
    bob_public = bob_rsa.get_public_key()
    print(f"   Public key: (e={bob_public[0]}, n={bob_public[1]})")
    print(f"   Key size: {bob_public[1].bit_length()} bits")
    
    # Bob publishes his public key
    print("\n2. Bob publishes his public key")
    
    # Alice encrypts a message
    message = "Hello Bob! This is a secret message."
    print(f"\n3. Alice's original message: '{message}'")
    
    print("\n4. Alice encrypts the message using Bob's public key")
    ciphertext = bob_rsa.encrypt(message, bob_public)
    print(f"   Ciphertext: {ciphertext}")
    
    # Bob decrypts the message
    print("\n5. Bob decrypts the message using his private key")
    decrypted = bob_rsa.decrypt(ciphertext)
    
    # Convert back to string
    decrypted_str = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, byteorder='big').decode()
    print(f"   Decrypted message: '{decrypted_str}'")
    
    print(f"\n6. Message successfully decrypted: {decrypted_str == message}")
    
    print("\n" + "=" * 70)
    print("RSA encryption ensures only Bob can read the message!")
    print("=" * 70)


def demonstrate_rsa_signatures():
    """
    Demonstrate RSA digital signatures.
    """
    print("\n" + "=" * 70)
    print(" " * 20 + "RSA DIGITAL SIGNATURES")
    print("=" * 70)
    
    print("\nScenario: Alice wants to prove she wrote a message.\n")
    
    # Alice generates RSA keys
    print("1. Alice generates RSA key pair")
    alice_rsa = RSA(key_size=1024)
    alice_rsa.generate_keys()
    
    alice_public = alice_rsa.get_public_key()
    print(f"   Alice publishes her public key")
    
    # Alice signs a message
    message = "I, Alice, agree to the terms of this contract."
    print(f"\n2. Alice's message: '{message}'")
    
    print("\n3. Alice signs the message with her private key")
    signature = alice_rsa.sign(message)
    print(f"   Signature: {signature}")
    
    # Anyone can verify with Alice's public key
    print("\n4. Bob verifies the signature using Alice's public key")
    verified = alice_rsa.verify(message, signature, alice_public)
    print(f"   Signature valid: {verified}")
    
    # Try to tamper with the message
    print("\n5. Mallory tries to modify the message")
    tampered = "I, Alice, agree to transfer $1,000,000."
    print(f"   Tampered message: '{tampered}'")
    
    print("\n6. Verification with tampered message")
    tampered_verified = alice_rsa.verify(tampered, signature, alice_public)
    print(f"   Signature valid: {tampered_verified}")
    
    print("\n" + "=" * 70)
    print("Digital signatures ensure authenticity and integrity!")
    print("=" * 70)


def main_menu():
    """
    Display menu and run demonstrations.
    """
    print("\n" + "=" * 70)
    print(" " * 10 + "D-H AND RSA CRYPTOGRAPHY DEMONSTRATIONS")
    print(" " * 15 + "Object-Oriented Implementation")
    print("=" * 70)
    
    while True:
        print("\n\nSelect a demonstration:")
        print("\n  BASIC DEMONSTRATIONS:")
        print("    1. Diffie-Hellman Key Exchange")
        print("    2. RSA Encryption/Decryption")
        print("    3. RSA Digital Signatures")
        print("\n  SECURITY ANALYSIS:")
        print("    4. Diffie-Hellman: Attacks and Defenses")
        print("    5. RSA: Attacks and Defenses")
        print("\n  OTHER:")
        print("    6. Run All Demonstrations")
        print("    0. Exit")
        
        choice = input("\nEnter your choice (0-6): ").strip()
        
        if choice == '1':
            demonstrate_dh_basic()
        elif choice == '2':
            demonstrate_rsa_basic()
        elif choice == '3':
            demonstrate_rsa_signatures()
        elif choice == '4':
            demonstrate_dh_attacks_and_defenses()
        elif choice == '5':
            demonstrate_rsa_attacks_and_defenses()
        elif choice == '6':
            demonstrate_dh_basic()
            demonstrate_rsa_basic()
            demonstrate_rsa_signatures()
            demonstrate_dh_attacks_and_defenses()
            demonstrate_rsa_attacks_and_defenses()
        elif choice == '0':
            print("\nThank you for using the cryptography demonstration!")
            break
        else:
            print("\nInvalid choice. Please try again.")
        
        input("\n\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Exiting...")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
