"""
Attacks and Defenses for Diffie-Hellman Key Exchange

This module demonstrates various attacks on D-H and their countermeasures.
"""

import random
from diffie_hellman import DiffieHellman


class DHAttacks:
    """
    Demonstration of various attacks on Diffie-Hellman key exchange.
    """
    
    @staticmethod
    def man_in_the_middle_attack():
        """
        Demonstrate Man-in-the-Middle (MITM) attack on D-H.
        
        In this attack, an attacker intercepts the key exchange and
        establishes separate shared secrets with both parties.
        """
        print("=" * 60)
        print("Man-in-the-Middle Attack on Diffie-Hellman")
        print("=" * 60)
        
        # Alice and Bob create their D-H instances
        alice = DiffieHellman()
        bob = DiffieHellman()
        
        # Get common parameters
        p, g = alice.get_parameters()
        bob.prime = p
        bob.generator = g
        
        # Alice generates her keys
        alice.generate_private_key()
        alice_public = alice.generate_public_key()
        print(f"\n1. Alice generates public key: {alice_public}")
        
        # Bob generates his keys
        bob.generate_private_key()
        bob_public = bob.generate_public_key()
        print(f"2. Bob generates public key: {bob_public}")
        
        # Attacker (Eve) intercepts the exchange
        eve_to_alice = DiffieHellman()
        eve_to_bob = DiffieHellman()
        
        eve_to_alice.prime = p
        eve_to_alice.generator = g
        eve_to_bob.prime = p
        eve_to_bob.generator = g
        
        # Eve generates keys to communicate with Alice
        eve_to_alice.generate_private_key()
        eve_public_for_alice = eve_to_alice.generate_public_key()
        
        # Eve generates keys to communicate with Bob
        eve_to_bob.generate_private_key()
        eve_public_for_bob = eve_to_bob.generate_public_key()
        
        print(f"\n3. Eve intercepts and sends her public key to Alice: {eve_public_for_alice}")
        print(f"4. Eve intercepts and sends her public key to Bob: {eve_public_for_bob}")
        
        # Alice computes shared secret with Eve (thinking it's Bob)
        alice_shared = alice.compute_shared_secret(eve_public_for_alice)
        
        # Bob computes shared secret with Eve (thinking it's Alice)
        bob_shared = bob.compute_shared_secret(eve_public_for_bob)
        
        # Eve computes shared secrets with both
        eve_shared_with_alice = eve_to_alice.compute_shared_secret(alice_public)
        eve_shared_with_bob = eve_to_bob.compute_shared_secret(bob_public)
        
        print(f"\n5. Alice's shared secret: {alice_shared}")
        print(f"6. Eve's shared secret with Alice: {eve_shared_with_alice}")
        print(f"7. Bob's shared secret: {bob_shared}")
        print(f"8. Eve's shared secret with Bob: {eve_shared_with_bob}")
        
        print(f"\nAttack successful: {alice_shared == eve_shared_with_alice and bob_shared == eve_shared_with_bob}")
        print("\nEve can now decrypt and re-encrypt all messages between Alice and Bob!")
        
        return {
            'alice_shared': alice_shared,
            'bob_shared': bob_shared,
            'eve_alice': eve_shared_with_alice,
            'eve_bob': eve_shared_with_bob
        }
    
    @staticmethod
    def small_subgroup_attack():
        """
        Demonstrate small subgroup attack.
        
        An attacker can send a public key that belongs to a small subgroup,
        limiting the possible shared secrets to a small set of values.
        """
        print("\n" + "=" * 60)
        print("Small Subgroup Attack on Diffie-Hellman")
        print("=" * 60)
        
        # Use a small prime for demonstration
        p = 23  # Small prime for demonstration
        g = 5
        
        alice = DiffieHellman(prime=p, generator=g)
        alice.generate_private_key()
        alice_public = alice.generate_public_key()
        
        print(f"\n1. Using small parameters: p={p}, g={g}")
        print(f"2. Alice's public key: {alice_public}")
        
        # Attacker sends a small subgroup element (e.g., 1)
        # If Alice doesn't validate, shared secret will always be 1
        malicious_public_key = 1
        
        print(f"3. Attacker sends malicious public key: {malicious_public_key}")
        
        try:
            # Try to compute shared secret (will fail with proper validation)
            shared = alice.compute_shared_secret(malicious_public_key)
            print(f"4. Shared secret computed: {shared}")
            print("\nAttack successful! Shared secret is predictable.")
        except ValueError as e:
            print(f"4. Attack prevented! Error: {e}")
            print("\nProper validation prevents this attack.")
        
        return None


class DHDefenses:
    """
    Demonstration of defense mechanisms against D-H attacks.
    """
    
    @staticmethod
    def authenticated_key_exchange():
        """
        Demonstrate authenticated D-H key exchange using digital signatures.
        
        This prevents MITM attacks by authenticating the public keys.
        """
        print("\n" + "=" * 60)
        print("Authenticated Diffie-Hellman Key Exchange (Defense against MITM)")
        print("=" * 60)
        
        # For authentication, we'll use RSA signatures
        # In production, use proper certificate infrastructure
        from rsa import RSA
        
        # Alice and Bob each have their own RSA key pairs for authentication
        alice_rsa = RSA(key_size=1024)  # Smaller for demo
        alice_rsa.generate_keys()
        
        bob_rsa = RSA(key_size=1024)
        bob_rsa.generate_keys()
        
        # Alice and Bob know each other's public keys (pre-shared or via PKI)
        alice_auth_public = alice_rsa.get_public_key()
        bob_auth_public = bob_rsa.get_public_key()
        
        print("\n1. Alice and Bob have pre-shared authentication keys (RSA)")
        
        # Perform D-H key exchange
        alice = DiffieHellman()
        bob = DiffieHellman()
        
        p, g = alice.get_parameters()
        bob.prime = p
        bob.generator = g
        
        # Generate D-H keys
        alice.generate_private_key()
        alice_public = alice.generate_public_key()
        
        bob.generate_private_key()
        bob_public = bob.generate_public_key()
        
        print(f"2. Alice's D-H public key: {alice_public}")
        print(f"3. Bob's D-H public key: {bob_public}")
        
        # Sign the public keys
        alice_signature = alice_rsa.sign(str(alice_public).encode())
        bob_signature = bob_rsa.sign(str(bob_public).encode())
        
        print(f"\n4. Alice signs her public key: {alice_signature}")
        print(f"5. Bob signs his public key: {bob_signature}")
        
        # Verify signatures before computing shared secret
        alice_verified = bob_rsa.verify(str(alice_public).encode(), alice_signature, alice_auth_public)
        bob_verified = alice_rsa.verify(str(bob_public).encode(), bob_signature, bob_auth_public)
        
        print(f"\n6. Bob verifies Alice's signature: {alice_verified}")
        print(f"7. Alice verifies Bob's signature: {bob_verified}")
        
        if alice_verified and bob_verified:
            # Compute shared secrets
            alice_shared = alice.compute_shared_secret(bob_public)
            bob_shared = bob.compute_shared_secret(alice_public)
            
            print(f"\n8. Shared secrets computed successfully")
            print(f"   Alice's shared secret matches Bob's: {alice_shared == bob_shared}")
            print("\nMITM attack prevented through authentication!")
        else:
            print("\nSignature verification failed! Possible MITM attack detected.")
        
        return alice_verified and bob_verified
    
    @staticmethod
    def secure_parameter_selection():
        """
        Demonstrate the importance of proper parameter selection.
        """
        print("\n" + "=" * 60)
        print("Secure Parameter Selection (Defense against various attacks)")
        print("=" * 60)
        
        print("\n1. Using large safe primes (2048+ bits)")
        print("2. Proper generator selection")
        print("3. Key validation before computing shared secret")
        
        # Create instance with secure parameters
        dh = DiffieHellman(key_size=2048)
        
        print(f"\n4. Prime size: {dh.prime.bit_length()} bits")
        print(f"5. Generator: {dh.generator}")
        
        dh.generate_private_key()
        dh.generate_public_key()
        
        # Test validation
        print("\n6. Testing public key validation:")
        
        # Valid key
        valid_key = pow(dh.generator, random.randint(2, dh.prime - 2), dh.prime)
        print(f"   Valid key test: {dh._validate_public_key(valid_key)}")
        
        # Invalid keys
        print(f"   Invalid key (0): {dh._validate_public_key(0)}")
        print(f"   Invalid key (1): {dh._validate_public_key(1)}")
        print(f"   Invalid key (p): {dh._validate_public_key(dh.prime)}")
        
        print("\nProper parameter selection significantly improves security!")
        
        return True


def demonstrate_dh_attacks_and_defenses():
    """
    Run all D-H attack and defense demonstrations.
    """
    print("\n" + "=" * 70)
    print(" " * 15 + "DIFFIE-HELLMAN ATTACKS AND DEFENSES")
    print("=" * 70)
    
    attacks = DHAttacks()
    defenses = DHDefenses()
    
    # Demonstrate attacks
    print("\n\nPART 1: ATTACKS")
    print("-" * 70)
    
    attacks.man_in_the_middle_attack()
    attacks.small_subgroup_attack()
    
    # Demonstrate defenses
    print("\n\nPART 2: DEFENSES")
    print("-" * 70)
    
    defenses.authenticated_key_exchange()
    defenses.secure_parameter_selection()
    
    print("\n" + "=" * 70)
    print("Demonstration complete!")
    print("=" * 70)


if __name__ == "__main__":
    demonstrate_dh_attacks_and_defenses()
