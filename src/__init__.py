"""
Cryptographic Algorithms Package

This package contains object-oriented implementations of:
- Diffie-Hellman key exchange
- RSA encryption/decryption
- Demonstrations of attacks and defenses
"""

__version__ = "1.0.0"
__author__ = "Cryptography Education Project"

from .diffie_hellman import DiffieHellman
from .rsa import RSA

__all__ = ['DiffieHellman', 'RSA']
