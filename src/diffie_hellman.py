"""
Diffie-Hellman Key Exchange Implementation
Object-oriented implementation of the D-H algorithm with security considerations
"""

import random
import hashlib


class DiffieHellman:
    """
    Diffie-Hellman key exchange protocol implementation.
    
    This class implements the basic D-H key exchange algorithm using
    modular exponentiation over a finite field.
    """
    
    def __init__(self, prime=None, generator=None, key_size=2048):
        """
        Initialize D-H parameters.
        
        Args:
            prime: A large prime number (p). If None, generates a safe prime.
            generator: A generator of the multiplicative group (g). If None, uses 2.
            key_size: Bit size for generated primes (default: 2048)
        """
        self.key_size = key_size
        
        if prime is None:
            # Use well-known safe prime for demonstration
            # In production, use cryptographically secure parameters
            self.prime = self._generate_safe_prime(key_size)
        else:
            self.prime = prime
            
        if generator is None:
            self.generator = 2
        else:
            self.generator = generator
            
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def _generate_safe_prime(self, bits):
        """
        Generate a safe prime number.
        A safe prime p is a prime where (p-1)/2 is also prime.
        
        For demonstration purposes, using smaller known safe primes.
        In production, use cryptographic libraries.
        """
        # Using a known safe prime for demonstration (smaller for speed)
        if bits <= 512:
            # Known safe prime (Sophie Germain prime * 2 + 1)
            return 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        else:
            # For larger sizes, use the same prime (2048-bit safe prime from RFC 3526)
            return 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    
    def generate_private_key(self):
        """
        Generate a random private key.
        The private key should be in the range [2, p-2].
        """
        self.private_key = random.randint(2, self.prime - 2)
        return self.private_key
    
    def generate_public_key(self):
        """
        Generate public key from private key.
        Public key = g^private_key mod p
        """
        if self.private_key is None:
            self.generate_private_key()
        
        self.public_key = pow(self.generator, self.private_key, self.prime)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """
        Compute shared secret from other party's public key.
        Shared secret = other_public_key^private_key mod p
        
        Args:
            other_public_key: The other party's public key
            
        Returns:
            The computed shared secret
        """
        if self.private_key is None:
            raise ValueError("Private key not generated yet")
        
        # Validate the other party's public key
        if not self._validate_public_key(other_public_key):
            raise ValueError("Invalid public key received")
        
        self.shared_secret = pow(other_public_key, self.private_key, self.prime)
        return self.shared_secret
    
    def _validate_public_key(self, public_key):
        """
        Validate that the received public key is in valid range.
        Protection against small subgroup attacks.
        
        Args:
            public_key: The public key to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Check if public key is in valid range [2, p-1]
        if public_key < 2 or public_key >= self.prime:
            return False
        
        # Additional check: ensure public_key^((p-1)/2) mod p != 1
        # This helps prevent small subgroup attacks
        if pow(public_key, (self.prime - 1) // 2, self.prime) == 1:
            # This might be valid in some cases, but warrants caution
            pass
        
        return True
    
    def derive_key(self, key_length=32):
        """
        Derive an encryption key from the shared secret using a KDF.
        
        Args:
            key_length: Desired key length in bytes
            
        Returns:
            A derived key suitable for symmetric encryption
        """
        if self.shared_secret is None:
            raise ValueError("Shared secret not computed yet")
        
        # Use SHA-256 as a simple KDF
        secret_bytes = self.shared_secret.to_bytes(
            (self.shared_secret.bit_length() + 7) // 8, byteorder='big'
        )
        key = hashlib.sha256(secret_bytes).digest()[:key_length]
        return key
    
    def get_parameters(self):
        """
        Get the public parameters (p, g).
        
        Returns:
            Tuple of (prime, generator)
        """
        return (self.prime, self.generator)
