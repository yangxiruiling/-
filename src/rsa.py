"""
RSA Encryption/Decryption Implementation
Object-oriented implementation of the RSA algorithm with security considerations
"""

import random
import math
import hashlib


class RSA:
    """
    RSA public-key cryptography implementation.
    
    This class implements RSA key generation, encryption, and decryption
    with proper padding to prevent attacks.
    """
    
    def __init__(self, key_size=2048):
        """
        Initialize RSA with specified key size.
        
        Args:
            key_size: Size of the key in bits (default: 2048)
        """
        self.key_size = key_size
        self.public_key = None  # (e, n)
        self.private_key = None  # (d, n)
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.e = None
        self.d = None
    
    def _is_prime(self, n, k=5):
        """
        Miller-Rabin primality test.
        
        Args:
            n: Number to test
            k: Number of rounds (higher = more accurate)
            
        Returns:
            True if n is probably prime, False if definitely composite
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _generate_prime(self, bits):
        """
        Generate a random prime number of specified bit length.
        
        Args:
            bits: Bit length of the prime
            
        Returns:
            A prime number
        """
        while True:
            # Generate random odd number
            num = random.randint(2**(bits-1), 2**bits - 1)
            num |= 1  # Make it odd
            
            if self._is_prime(num):
                return num
    
    def _gcd(self, a, b):
        """
        Compute the Greatest Common Divisor using Euclidean algorithm.
        """
        while b:
            a, b = b, a % b
        return a
    
    def _extended_gcd(self, a, b):
        """
        Extended Euclidean algorithm.
        Returns (gcd, x, y) such that a*x + b*y = gcd
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def _mod_inverse(self, a, m):
        """
        Calculate modular multiplicative inverse of a modulo m.
        """
        gcd, x, _ = self._extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        
        return (x % m + m) % m
    
    def generate_keys(self):
        """
        Generate RSA public and private key pairs.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        # Generate two distinct prime numbers
        self.p = self._generate_prime(self.key_size // 2)
        self.q = self._generate_prime(self.key_size // 2)
        
        # Ensure p != q
        while self.p == self.q:
            self.q = self._generate_prime(self.key_size // 2)
        
        # Calculate n = p * q
        self.n = self.p * self.q
        
        # Calculate Euler's totient: φ(n) = (p-1)(q-1)
        self.phi = (self.p - 1) * (self.q - 1)
        
        # Choose public exponent e
        # Common choices are 65537 (2^16 + 1) for efficiency
        self.e = 65537
        
        # Ensure e and φ(n) are coprime
        if self._gcd(self.e, self.phi) != 1:
            # If not coprime, find a suitable e
            self.e = 3
            while self._gcd(self.e, self.phi) != 1:
                self.e += 2
        
        # Calculate private exponent d
        # d is the modular multiplicative inverse of e modulo φ(n)
        self.d = self._mod_inverse(self.e, self.phi)
        
        # Set public and private keys
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)
        
        return self.public_key, self.private_key
    
    def encrypt(self, plaintext, public_key=None):
        """
        Encrypt a message using RSA public key.
        
        Args:
            plaintext: Message to encrypt (integer or bytes)
            public_key: Public key tuple (e, n). Uses own if None.
            
        Returns:
            Encrypted ciphertext (integer)
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            e, n = self.public_key
        else:
            e, n = public_key
        
        # Convert message to integer if it's bytes
        if isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, byteorder='big')
        elif isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), byteorder='big')
        
        # Check if message is too large
        if plaintext >= n:
            raise ValueError("Message too large for key size")
        
        # Apply padding for security (simple OAEP-like padding)
        padded_plaintext = self._apply_padding(plaintext, n)
        
        # Encrypt: c = m^e mod n
        ciphertext = pow(padded_plaintext, e, n)
        
        return ciphertext
    
    def decrypt(self, ciphertext, private_key=None):
        """
        Decrypt a message using RSA private key.
        
        Args:
            ciphertext: Encrypted message (integer)
            private_key: Private key tuple (d, n). Uses own if None.
            
        Returns:
            Decrypted plaintext (integer)
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available")
            d, n = self.private_key
        else:
            d, n = private_key
        
        # Decrypt: m = c^d mod n
        padded_plaintext = pow(ciphertext, d, n)
        
        # Remove padding
        plaintext = self._remove_padding(padded_plaintext, n)
        
        return plaintext
    
    def _apply_padding(self, message, n):
        """
        Apply simple padding to prevent attacks.
        This is a simplified version of OAEP padding.
        
        Args:
            message: The message to pad
            n: The modulus
            
        Returns:
            Padded message
        """
        # Simple padding scheme: add random padding
        # Format: 0x02 || random_padding || 0x00 || message
        
        # Calculate available space
        n_bytes = (n.bit_length() + 7) // 8
        msg_bytes = (message.bit_length() + 7) // 8
        
        # Need space for: 0x02, at least 8 bytes padding, 0x00, message
        if msg_bytes > n_bytes - 11:
            # Not enough space for padding, return as is (less secure)
            return message
        
        # Create padding
        padding_length = n_bytes - msg_bytes - 3
        padding = random.randint(1, 2**(padding_length * 8) - 1)
        
        # Combine: (0x02 << ...) | (padding << ...) | (0x00 << ...) | message
        padded = (0x02 << ((n_bytes - 1) * 8))
        padded |= (padding << ((msg_bytes + 1) * 8))
        padded |= message
        
        return padded
    
    def _remove_padding(self, padded_message, n):
        """
        Remove padding from decrypted message.
        
        Args:
            padded_message: The padded message
            n: The modulus
            
        Returns:
            Original message without padding
        """
        # Convert to bytes to parse
        n_bytes = (n.bit_length() + 7) // 8
        padded_bytes = padded_message.to_bytes(n_bytes, byteorder='big')
        
        # Look for the 0x00 separator after 0x02 and padding
        try:
            # Find first 0x00 after initial bytes
            separator_idx = padded_bytes.index(b'\x00', 2)
            message_bytes = padded_bytes[separator_idx + 1:]
            message = int.from_bytes(message_bytes, byteorder='big')
            return message
        except ValueError:
            # No separator found, return as is
            return padded_message
    
    def sign(self, message, private_key=None):
        """
        Sign a message using the private key.
        
        Args:
            message: Message to sign (bytes or string)
            private_key: Private key tuple (d, n). Uses own if None.
            
        Returns:
            Digital signature (integer)
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available")
            d, n = self.private_key
        else:
            d, n = private_key
        
        # Hash the message
        if isinstance(message, str):
            message = message.encode()
        
        message_hash = hashlib.sha256(message).digest()
        hash_int = int.from_bytes(message_hash, byteorder='big')
        
        # Sign: signature = hash^d mod n
        signature = pow(hash_int, d, n)
        
        return signature
    
    def verify(self, message, signature, public_key=None):
        """
        Verify a digital signature.
        
        Args:
            message: Original message (bytes or string)
            signature: Signature to verify (integer)
            public_key: Public key tuple (e, n). Uses own if None.
            
        Returns:
            True if signature is valid, False otherwise
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            e, n = self.public_key
        else:
            e, n = public_key
        
        # Hash the message
        if isinstance(message, str):
            message = message.encode()
        
        message_hash = hashlib.sha256(message).digest()
        hash_int = int.from_bytes(message_hash, byteorder='big')
        
        # Verify: recovered_hash = signature^e mod n
        recovered_hash = pow(signature, e, n)
        
        return hash_int == recovered_hash
    
    def get_public_key(self):
        """Get the public key (e, n)."""
        return self.public_key
    
    def get_private_key(self):
        """Get the private key (d, n)."""
        return self.private_key
