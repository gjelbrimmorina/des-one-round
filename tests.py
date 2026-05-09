"""
Teste automatike per implementimin e nje round-i te DES-it.
Lesho me: python3 tests.py
"""

from des_one_round import (
    des_one_round, hex_to_bits, bits_to_hex,
    permute, IP, IP_INVERSE, f_function
)


def test(name, condition, details=""):
    """Funksion ndihmes per te printuar rezultatin e testit."""
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}")
    if details and not condition:
        print(f"         {details}")
    return condition


def run_all_tests():
    print("=" * 60)
    print("  AUTOMATED TESTS - ONE-ROUND DES")
    print("=" * 60)

    passed = 0
    total = 0

    # Test 1: L1 duhet te jete e barabarte me R0
    print("\n[Test 1] Round structure: L1 = R0")
    pt = hex_to_bits("0123456789ABCDEF", 64)
    sk = hex_to_bits("1B02EFFC7072", 48)
    out = des_one_round(pt, sk, use_ip=False, verbose=False)
    L1 = out[:32]
    R0_original = pt[32:]
    total += 1
    if test("L1 == R0", L1 == R0_original,
            f"L1={bits_to_hex(L1)}, R0={bits_to_hex(R0_original)}"):
        passed += 1

    # Test 2: IP^-1(IP(x)) duhet te kthehet ne x
    print("\n[Test 2] IP and IP^-1 are mutual inverses")
    test_bits = [(i * 17) % 2 for i in range(64)]
    after_ip = permute(test_bits, IP)
    after_ip_inv = permute(after_ip, IP_INVERSE)
    total += 1
    if test("IP^-1(IP(x)) == x", after_ip_inv == test_bits):
        passed += 1

    # Test 3: Madhesia e dales duhet te jete 64-bit
    print("\n[Test 3] Output size = 64 bits")
    total += 1
    if test("len(output) == 64", len(out) == 64,
            f"got len={len(out)}"):
        passed += 1

    # Test 4: Funksioni f kthen 32-bit
    print("\n[Test 4] Function f returns 32 bits")
    R = hex_to_bits("89ABCDEF", 32)
    K = hex_to_bits("1B02EFFC7072", 48)
    f_out = f_function(R, K, verbose=False)
    total += 1
    if test("len(f(R,K)) == 32", len(f_out) == 32,
            f"got len={len(f_out)}"):
        passed += 1

    # Test 5: Vlere e njohur e f-funksionit (verifikim manual)
    # Per R=89ABCDEF, K=1B02EFFC7072, dalja e f duhet te jete AE89B20D
    print("\n[Test 5] Known value of f(R,K)")
    expected = "AE89B20D"
    total += 1
    if test(f"f(89ABCDEF, 1B02EFFC7072) == {expected}",
            bits_to_hex(f_out) == expected,
            f"got {bits_to_hex(f_out)}"):
        passed += 1

    # Test 6: SubKey i pavlefshem (gjatesi gabim) duhet te ngreje ValueError
    print("\n[Test 6] Input validation (wrong SubKey length)")
    error_raised = False
    try:
        des_one_round(pt, [0] * 47, use_ip=False, verbose=False)
    except ValueError:
        error_raised = True
    total += 1
    if test("ValueError for 47-bit SubKey", error_raised):
        passed += 1

    # Test 7: Plaintext i pavlefshem duhet te ngreje ValueError
    print("\n[Test 7] Input validation (wrong Plaintext length)")
    error_raised = False
    try:
        des_one_round([0] * 60, sk, use_ip=False, verbose=False)
    except ValueError:
        error_raised = True
    total += 1
    if test("ValueError for 60-bit Plaintext", error_raised):
        passed += 1

    # Test 8: Determinizmi - e njejta hyrje -> e njejta dalje
    print("\n[Test 8] Determinism (same input -> same output)")
    out_a = des_one_round(pt, sk, use_ip=True, verbose=False)
    out_b = des_one_round(pt, sk, use_ip=True, verbose=False)
    total += 1
    if test("Out(x,k) == Out(x,k) [deterministic]", out_a == out_b):
        passed += 1

    # Test 9: SubKey te ndryshem japin dalje te ndryshme
    print("\n[Test 9] Different SubKeys -> different outputs")
    sk1 = hex_to_bits("1B02EFFC7072", 48)
    sk2 = hex_to_bits("AAAAAAAAAAAA", 48)
    out1 = des_one_round(pt, sk1, use_ip=True, verbose=False)
    out2 = des_one_round(pt, sk2, use_ip=True, verbose=False)
    total += 1
    if test("Out(x,k1) != Out(x,k2)", out1 != out2):
        passed += 1

    # Test 10: Konvertimet hex<->bit jane konzistente
    print("\n[Test 10] hex <-> bits conversion is consistent")
    hex_orig = "DEADBEEFCAFEBABE"
    bits = hex_to_bits(hex_orig, 64)
    hex_back = bits_to_hex(bits)
    total += 1
    if test(f"hex_to_bits('{hex_orig}') -> bits -> hex == '{hex_orig}'",
            hex_back == hex_orig,
            f"got {hex_back}"):
        passed += 1

    # Permbledhja
    print("\n" + "=" * 60)
    print(f"  RESULT: {passed}/{total} tests passed")
    print("=" * 60)
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)