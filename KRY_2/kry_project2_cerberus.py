#!/usr/bin/env python3
"""
PROJECT CERBERUS: Secure Multiparty Signatures
Starter Template

Dependencies: pip install py_ecc

Author: xkucik00 (241451)
email: xkucik00@stud.fit.vutbr.cz
"""
import pickle  # To serialize pk into bytes
import secrets # For secure random generator
import hashlib
from py_ecc.optimized_bls12_381.optimized_curve import G1, G2, multiply, add, neg
from py_ecc.optimized_bls12_381.optimized_pairing import pairing
"""
py_ecc's optimized_bls12_381 module provides efficient implementations of the BLS12-381 curve.

parameters:
- G1 and G2: These are the base generator points for the two elliptic curve groups used in BLS signatures.
    In standard BLS implementations, signatures are typically mapped to points on G1 (to keep the signature size small), 
    and public keys are calculated as points on G2 (to leverage the security properties of the larger group).
- multiply: This function performs scalar multiplication on the elliptic curve. Used for key generation and signing.
- add: This function performs point addition on the elliptic curve. Used for aggregating keys and signatures.
- neg: Computes the inverse (or negative) of a point on the elliptic curve. Used for crafting rogue keys in the attack phase.
- pairing: The absolute heart of the BLS cryptography. This function computes the bilinear pairing e(Q, P) 
    between a point P from G1 and a point Q from G2, mapping them to a complex target field. This property is what allows 
    BLS signatures to be aggregated and verified efficiently. Used for veryfing signatures against public keys.
"""

# ==============================================================================
# Helper functions
# ==============================================================================

def simple_hash_to_G1(message: bytes) -> tuple:
    """
    Maps a byte string to a point on G1.
    
    In production, you must use a secure hash-to-curve algorithm (RFC 9380).
    For this assignment, we use a simple scalar multiplication of the generator.
    """
    digest = hashlib.sha256(message).digest()
    scalar = int.from_bytes(digest, 'big')
    return multiply(G1, scalar)

# ==============================================================================
# PHASE 1: BUILDING CERBERUS
# ==============================================================================

def generate_keypair() -> tuple:
    """
    TODO: Generate a random private key (scalar) and its corresponding public key.
    In BLS, public keys are typically points on G2. Make sure to use secure randomness for the private key!
    
    Returns:
        sk (int): The private key.
        pk (tuple): The public key (point on G2).
    """
    sk = secrets.randbits(256)
    pk = multiply(G2, sk)
    return sk, pk

def sign(sk: int, message: bytes) -> tuple:
    """
    TODO: Sign a message using the private key.
    Hash the message to G1, then multiply by the secret key.
    
    Returns:
        signature (tuple): The signature (point on G1).
    """
    hashed_message = simple_hash_to_G1(message)
    signature = multiply(hashed_message, sk)
    return signature

def aggregate_public_keys(public_keys: list) -> tuple:
    """
    TODO: Aggregate a list of public keys into a single joint public key.
    
    Returns:
        agg_pk (tuple): The aggregated public key (point on G2).
    """
    agg_pk = public_keys[0]

    for i in range(1, len(public_keys)):
        agg_pk = add(agg_pk, public_keys[i])
    
    return agg_pk

def aggregate_signatures(signatures: list) -> tuple:
    """
    TODO: Aggregate a list of signatures into a single joint signature.
    
    Returns:
        agg_sig (tuple): The aggregated signature (point on G1).
    """
    agg_sig = signatures[0]

    for i in range(1, len(signatures)):
        agg_sig = add(agg_sig, signatures[i])
    
    return agg_sig

def verify(pk: tuple, sig: tuple, message: bytes) -> bool:
    """
    TODO: Verify a signature against a public key.
    (Hint: use the pairing function)
    
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    hashed_message = simple_hash_to_G1(message)
    l_pair = pairing(G2, sig)
    r_pair = pairing(pk, hashed_message)

    if (l_pair == r_pair):
        return True
    else:
        return False


# ==============================================================================
# PHASE 2: THE INSIDE JOB
# ==============================================================================

def generate_rogue_key(bob_sk: int, alice_pk: tuple, charlie_pk: tuple) -> tuple:
    """
    TODO: Craft a malicious public key (hint: use the neg function).

    Returns:
        pk_prime_bob (tuple): Bob's forged public key (point on G2).
    """
    pk_true_bob = multiply(G2, bob_sk)
    pk_prime_bob = add(pk_true_bob, neg(alice_pk))
    pk_prime_bob = add(pk_prime_bob, neg(charlie_pk))
    return pk_prime_bob

# ==============================================================================
# PHASE 3: SECURING CERBERUS
# ==============================================================================

def prove_possesion(sk: int, pk: tuple) -> tuple:
    """
    TODO: Create a Proof of Possession. Serialize the pk to bytes for hashing.
    
    Returns:
        proof_sig (tuple): Signature over the public key (point on G1).
    """
    bytes_pk = pickle.dumps(pk)
    hashed_pk = simple_hash_to_G1(bytes_pk)

    proof_sig = multiply(hashed_pk, sk)

    return proof_sig

def verify_pop(pk: tuple, proof_sig: tuple) -> bool:
    """
    TODO: Verify the Proof of Possession.
    
    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    bytes_pk = pickle.dumps(pk)
    hashed_pk = simple_hash_to_G1(bytes_pk)
    r_pair = pairing(pk, hashed_pk)
    l_pair = pairing(G2, proof_sig)

    if (l_pair == r_pair):
        return True
    else:
        return False
