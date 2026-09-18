from kry_project2_cerberus import *

def test_1():
    # Common tests - generate, sign, verify
    sk1, pk1 = generate_keypair()

    message1 = b"Hello world!"
    message2 = b"42"
    
    sig = sign(sk1,message1)
    assert verify(pk1, sig, message1) == True
    assert verify(pk1, sig, message2) == False

    sk2, pk2 = generate_keypair()
    assert verify(pk2, sig, message1) == False

    # Aggregation test
    sk3, pk3 = generate_keypair()

    sig1 = sign(sk1, message1)
    sig2 = sign(sk2, message1)
    sig3 = sign(sk3, message1)

    agg_pk = aggregate_public_keys([pk1, pk2, pk3])
    agg_sig = aggregate_signatures([sig1, sig2, sig3])

    assert verify(agg_pk, agg_sig, message1) == True

    print("Tests 1 passed")

def test_2():
    # Rouge test
    message = b"Tests 1 passed"
    _, pk_a = generate_keypair()
    _, pk_c = generate_keypair()

    sk_b = 28461274712
    pk_prime_b = generate_rogue_key(sk_b, pk_a, pk_c)

    agg_pk = aggregate_public_keys([pk_prime_b, pk_a, pk_c])
    rogue_sig = sign(sk_b, message)

    assert verify(agg_pk, rogue_sig, message) == True # Verified

    print("Tests 2 passed")

def test_3():
    # Proof of Possession test
    sk_a, pk_a = generate_keypair()
    sk_c, pk_c = generate_keypair()

    proof_a = prove_possesion(sk_a, pk_a)
    assert verify_pop(pk_a, proof_a) == True # Verified

    proof_c = prove_possesion(sk_c, pk_c)
    assert verify_pop(pk_c, proof_c) == True # Verified

    sk_b = 28461274712
    pk_prime_b = generate_rogue_key(sk_b, pk_a, pk_c)
    proof_b = prove_possesion(sk_b, pk_prime_b)
    
    # Cannot verify with rogue key
    assert verify_pop(pk_prime_b, proof_b) == False 

    print("Tests 3 passed")

if __name__ == "__main__":
    test_1()
    test_2()
    test_3()
