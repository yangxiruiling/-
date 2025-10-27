"""
Attacks and Defenses for RSA Encryption

This module demonstrates various attacks on RSA and their countermeasures.
"""

import math
from rsa import RSA


class RSAAttacks:
    """
    Demonstration of various attacks on RSA encryption.
    """
    
    @staticmethod
    def small_exponent_attack():
        """
        Demonstrate small public exponent attack.
        
        When the public exponent e is small and the message m is such that
        m^e < n, the ciphertext c = m^e can be decrypted by simply taking
        the e-th root without needing to use modular arithmetic.
        """
        print("=" * 60)
        print("Small Exponent Attack on RSA")
        print("=" * 60)
        
        # Create RSA with small key for demonstration
        rsa = RSA(key_size=512)
        rsa.generate_keys()
        
        e, n = rsa.get_public_key()
        
        print(f"\n1. RSA parameters:")
        print(f"   Public exponent (e): {e}")
        print(f"   Modulus (n): {n}")
        print(f"   Key size: {n.bit_length()} bits")
        
        # Choose a small message
        small_message = 42
        
        print(f"\n2. Original message: {small_message}")
        
        # Check if m^e < n (vulnerable to attack)
        m_to_e = small_message ** e
        vulnerable = m_to_e < n
        
        print(f"3. Is m^e < n? {vulnerable}")
        
        if vulnerable:
            # Encrypt without padding (vulnerable)
            # We'll directly compute m^e mod n to simulate no padding
            ciphertext = pow(small_message, e, n)
            
            print(f"4. Ciphertext: {ciphertext}")
            
            # Attack: Take the e-th root
            # Since m^e < n, ciphertext = m^e (no modular reduction)
            if ciphertext < n:
                recovered = int(ciphertext ** (1.0 / e))
                print(f"5. Recovered message by taking {e}-th root: {recovered}")
                print(f"\nAttack successful: {recovered == small_message}")
            else:
                print("5. Modular reduction occurred, simple root won't work")
        else:
            print("4. Message is large enough, attack won't work directly")
        
        print("\nDefense: Use proper padding (OAEP) to make m large and random")
        
        # Demonstrate with padding
        ciphertext_padded = rsa.encrypt(small_message)
        decrypted = rsa.decrypt(ciphertext_padded)
        
        print(f"\n6. With padding:")
        print(f"   Encrypted (with padding): {ciphertext_padded}")
        print(f"   Decrypted correctly: {decrypted == small_message}")
        
        return vulnerable
    
    @staticmethod
    def factorization_attack():
        """
        Demonstrate factorization attack on RSA with small primes.
        
        If n can be factored into p and q, the private key can be computed.
        """
        print("\n" + "=" * 60)
        print("Factorization Attack on RSA with Small Primes")
        print("=" * 60)
        
        # Create RSA with very small primes for demonstration
        # In practice, this would take years for large primes
        small_p = 61
        small_q = 53
        
        print(f"\n1. Using small primes for demonstration:")
        print(f"   p = {small_p}")
        print(f"   q = {small_q}")
        
        n = small_p * small_q
        phi = (small_p - 1) * (small_q - 1)
        e = 17
        
        # Compute d
        def mod_inverse(a, m):
            def extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y
            
            gcd, x, _ = extended_gcd(a, m)
            if gcd != 1:
                raise ValueError("Modular inverse does not exist")
            return (x % m + m) % m
        
        d = mod_inverse(e, phi)
        
        print(f"\n2. Public key: (e={e}, n={n})")
        print(f"3. Private key: (d={d}, n={n})")
        
        # Encrypt a message
        message = 42
        ciphertext = pow(message, e, n)
        
        print(f"\n4. Original message: {message}")
        print(f"5. Ciphertext: {ciphertext}")
        
        # Attack: Factor n
        print("\n6. Attacker attempts to factor n...")
        
        def trial_division(n):
            """Simple trial division factorization."""
            factors = []
            d = 2
            while d * d <= n:
                while n % d == 0:
                    factors.append(d)
                    n //= d
                d += 1
            if n > 1:
                factors.append(n)
            return factors
        
        factors = trial_division(n)
        
        if len(factors) == 2 and factors[0] != factors[1]:
            recovered_p, recovered_q = factors
            print(f"7. Factorization successful!")
            print(f"   Recovered p = {recovered_p}")
            print(f"   Recovered q = {recovered_q}")
            
            # Compute private key
            recovered_phi = (recovered_p - 1) * (recovered_q - 1)
            recovered_d = mod_inverse(e, recovered_phi)
            
            print(f"\n8. Computed private key: d = {recovered_d}")
            
            # Decrypt the message
            recovered_message = pow(ciphertext, recovered_d, n)
            print(f"9. Decrypted message: {recovered_message}")
            print(f"\nAttack successful: {recovered_message == message}")
        else:
            print("7. Factorization failed")
        
        print("\nDefense: Use large primes (1024+ bits each) that are hard to factor")
        
        return True
    
    @staticmethod
    def common_modulus_attack():
        """
        Demonstrate common modulus attack.
        
        If the same message is encrypted with the same modulus n but
        different exponents e1 and e2, and gcd(e1, e2) = 1, the plaintext
        can be recovered.
        """
        print("\n" + "=" * 60)
        print("Common Modulus Attack on RSA")
        print("=" * 60)
        
        # Two users sharing the same modulus (bad practice!)
        rsa1 = RSA(key_size=512)
        rsa1.generate_keys()
        
        e1, n = rsa1.get_public_key()
        
        # Create second user with same modulus but different e
        rsa2 = RSA(key_size=512)
        rsa2.n = n
        rsa2.p = rsa1.p
        rsa2.q = rsa1.q
        rsa2.phi = rsa1.phi
        
        # Choose different public exponent that is coprime with phi
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a
        
        # Try to find a suitable e2
        for candidate_e in [3, 5, 7, 11, 13, 17, 257, 65539]:
            if candidate_e != e1 and gcd(candidate_e, rsa2.phi) == 1:
                rsa2.e = candidate_e
                break
        else:
            # Fallback - use a large prime
            rsa2.e = 65539 if e1 != 65539 else 65543
        
        rsa2.d = rsa2._mod_inverse(rsa2.e, rsa2.phi)
        rsa2.public_key = (rsa2.e, n)
        rsa2.private_key = (rsa2.d, n)
        
        e2, _ = rsa2.get_public_key()
        
        print(f"\n1. Two users share modulus n")
        print(f"   User 1: e1 = {e1}")
        print(f"   User 2: e2 = {e2}")
        print(f"   Shared n: {n}")
        
        # Encrypt same message with both public keys
        message = 12345
        
        # Encrypt without padding for demonstration
        c1 = pow(message, e1, n)
        c2 = pow(message, e2, n)
        
        print(f"\n2. Same message encrypted twice:")
        print(f"   c1 = m^e1 mod n = {c1}")
        print(f"   c2 = m^e2 mod n = {c2}")
        
        # Check if attack is possible
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a
        
        if gcd(e1, e2) == 1:
            print(f"\n3. gcd(e1, e2) = 1, attack is possible!")
            
            # Extended Euclidean algorithm
            def extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd_val, x1, y1 = extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd_val, x, y
            
            _, s, t = extended_gcd(e1, e2)
            
            print(f"4. Using extended GCD: {e1}*{s} + {e2}*{t} = 1")
            
            # Compute m = c1^s * c2^t mod n
            if s < 0:
                c1_inv = pow(c1, -1, n)
                term1 = pow(c1_inv, -s, n)
            else:
                term1 = pow(c1, s, n)
            
            if t < 0:
                c2_inv = pow(c2, -1, n)
                term2 = pow(c2_inv, -t, n)
            else:
                term2 = pow(c2, t, n)
            
            recovered = (term1 * term2) % n
            
            print(f"5. Recovered message: {recovered}")
            print(f"\nAttack successful: {recovered == message}")
        else:
            print(f"\n3. gcd(e1, e2) ≠ 1, this particular attack won't work")
        
        print("\nDefense: Never share the same modulus n between different users!")
        
        return True
    
    @staticmethod
    def timing_attack_concept():
        """
        Explain timing attack concept.
        
        Timing attacks analyze the time taken for decryption operations
        to deduce information about the private key.
        """
        print("\n" + "=" * 60)
        print("Timing Attack Concept on RSA")
        print("=" * 60)
        
        print("""
Timing attacks exploit the fact that different operations take
different amounts of time. In RSA decryption:

    m = c^d mod n

The time to compute this depends on the bits of d. By measuring
decryption times for many ciphertexts, an attacker can potentially
recover bits of the private exponent d.

Attack process:
1. Send many chosen ciphertexts to the target
2. Measure the time taken for each decryption
3. Perform statistical analysis on timing variations
4. Deduce bits of the private key

Defense mechanisms:
1. Constant-time implementations (ensure all operations take the same time)
2. Blinding: randomize the ciphertext before decryption
   - Compute c' = c * r^e mod n for random r
   - Decrypt: m' = (c')^d mod n
   - Remove blinding: m = m' * r^(-1) mod n
3. Use timing-attack resistant algorithms (e.g., Montgomery multiplication)
        """)
        
        print("\nNote: This is a conceptual demonstration. Actual timing attacks")
        print("require precise measurements and statistical analysis.")
        
        return True


class RSADefenses:
    """
    Demonstration of defense mechanisms against RSA attacks.
    """
    
    @staticmethod
    def proper_padding_scheme():
        """
        Demonstrate the importance of proper padding (OAEP).
        """
        print("\n" + "=" * 60)
        print("Proper Padding Scheme (OAEP) Defense")
        print("=" * 60)
        
        rsa = RSA(key_size=1024)
        rsa.generate_keys()
        
        print("\n1. RSA with OAEP-like padding")
        print("   - Adds randomness to each encryption")
        print("   - Prevents deterministic encryption")
        print("   - Protects against chosen-plaintext attacks")
        
        # Use a simple integer message for demonstration
        message = 12345
        
        print(f"\n2. Original message: {message}")
        
        # Encrypt same message multiple times
        c1 = rsa.encrypt(message)
        c2 = rsa.encrypt(message)
        
        print(f"\n3. First encryption: {c1}")
        print(f"4. Second encryption: {c2}")
        print(f"5. Ciphertexts are different: {c1 != c2}")
        
        # Decrypt both
        m1 = rsa.decrypt(c1)
        m2 = rsa.decrypt(c2)
        
        print(f"\n6. First decryption: {m1}")
        print(f"7. Second decryption: {m2}")
        print(f"8. Both decrypt to original message: {m1 == message and m2 == message}")
        print(f"9. Decryptions match: {m1 == m2}")
        
        print("\nPadding makes RSA encryption non-deterministic and secure!")
        
        return True
    
    @staticmethod
    def secure_key_generation():
        """
        Demonstrate secure key generation practices.
        """
        print("\n" + "=" * 60)
        print("Secure Key Generation Defense")
        print("=" * 60)
        
        print("\n1. Use large key sizes (2048+ bits, prefer 3072 or 4096)")
        print("2. Generate strong random primes:")
        print("   - Use cryptographically secure random number generator")
        print("   - Ensure p and q are not close to each other")
        print("   - Check that |p - q| is large")
        print("3. Use safe public exponent (65537 is recommended)")
        print("4. Verify gcd(e, φ(n)) = 1")
        
        rsa = RSA(key_size=2048)
        rsa.generate_keys()
        
        e, n = rsa.get_public_key()
        
        print(f"\n5. Generated secure RSA keys:")
        print(f"   Key size: {n.bit_length()} bits")
        print(f"   Public exponent: {e}")
        print(f"   p and q are {rsa.p.bit_length()}-bit primes")
        
        # Check prime difference
        prime_diff = abs(rsa.p - rsa.q)
        print(f"   |p - q|: {prime_diff.bit_length()} bits")
        
        if prime_diff.bit_length() > 100:
            print("   ✓ Primes are sufficiently different")
        
        print("\nSecure key generation prevents many attacks!")
        
        return True
    
    @staticmethod
    def digital_signatures_for_authentication():
        """
        Demonstrate using RSA for digital signatures to ensure authenticity.
        """
        print("\n" + "=" * 60)
        print("Digital Signatures for Authentication Defense")
        print("=" * 60)
        
        # Alice generates RSA keys
        alice_rsa = RSA(key_size=1024)
        alice_rsa.generate_keys()
        
        message = "Transfer $1000 to Bob"
        
        print(f"\n1. Alice wants to send authenticated message: '{message}'")
        
        # Alice signs the message
        signature = alice_rsa.sign(message)
        
        print(f"2. Alice signs the message: {signature}")
        
        # Bob verifies the signature
        alice_public = alice_rsa.get_public_key()
        verified = alice_rsa.verify(message, signature, alice_public)
        
        print(f"3. Bob verifies signature: {verified}")
        
        # Try to tamper with the message
        tampered_message = "Transfer $9999 to Bob"
        tampered_verified = alice_rsa.verify(tampered_message, signature, alice_public)
        
        print(f"\n4. Attacker modifies message to: '{tampered_message}'")
        print(f"5. Verification with tampered message: {tampered_verified}")
        
        print("\nDigital signatures ensure message authenticity and integrity!")
        
        return verified and not tampered_verified


def demonstrate_rsa_attacks_and_defenses():
    """
    Run all RSA attack and defense demonstrations.
    """
    print("\n" + "=" * 70)
    print(" " * 20 + "RSA ATTACKS AND DEFENSES")
    print("=" * 70)
    
    attacks = RSAAttacks()
    defenses = RSADefenses()
    
    # Demonstrate attacks
    print("\n\nPART 1: ATTACKS")
    print("-" * 70)
    
    attacks.small_exponent_attack()
    attacks.factorization_attack()
    attacks.common_modulus_attack()
    attacks.timing_attack_concept()
    
    # Demonstrate defenses
    print("\n\nPART 2: DEFENSES")
    print("-" * 70)
    
    defenses.proper_padding_scheme()
    defenses.secure_key_generation()
    defenses.digital_signatures_for_authentication()
    
    print("\n" + "=" * 70)
    print("Demonstration complete!")
    print("=" * 70)


if __name__ == "__main__":
    demonstrate_rsa_attacks_and_defenses()
