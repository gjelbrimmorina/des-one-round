"""
============================================================
PROJEKTI III - SIGURIA E TE DHENAVE
Grupi 7: Implementimi i nje Round-i te Algoritmit DES
============================================================

Referenca: Internet Security - Cryptographic Principles,
Algorithms and Protocols (Man Young Rhee, 2003)
Figurat 3.1 dhe 3.2, faqe 59

KERKESAT:
- Implementohet vetem NJE round i DES-it
- SubKey-i NUK gjenerohet automatikisht
- SubKey-i jepet manualisht nga perdoruesi
- Te dhena hyrese: Plaintext 64-bit + SubKey 48-bit
============================================================
"""


# =====================================================================
# TABELAT STANDARDE TE DES-it (FIPS 46-3)
# =====================================================================

# Permutacioni Fillestar (Initial Permutation) - Figura 3.1
# Bllok 64-bit -> bllok 64-bit (rirenditje e bit-ave)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Permutacioni Final (i kunderti i IP-se) - Figura 3.1
IP_INVERSE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
]

# Tabela e Expansion E - Figura 3.2
# Zgjeron R-ne nga 32-bit ne 48-bit
E_TABLE = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

# Permutacioni P brenda funksionit f - Figura 3.2
# Pas S-Boxeve, perzien 32-bit-shit
P_TABLE = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
]

# 8 S-Boxet e DES-it - Figura 3.2
# Secili merr 6-bit hyrje dhe nxjerr 4-bit dalje
S_BOXES = [
    # S1
    [
        [14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7],
        [ 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8],
        [ 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0],
        [15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13]
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9]
    ],
    # S3
    [
        [10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
    ],
    # S4
    [
        [ 7, 13, 14, 3,  0,  6,  9, 10,  1, 2, 8,  5, 11, 12,  4, 15],
        [13,  8, 11, 5,  6, 15,  0,  3,  4, 7, 2, 12,  1, 10, 14,  9],
        [10,  6,  9, 0, 12, 11,  7, 13, 15, 1, 3, 14,  5,  2,  8,  4],
        [ 3, 15,  0, 6, 10,  1, 13,  8,  9, 4, 5, 11, 12,  7,  2, 14]
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3]
    ],
    # S6
    [
        [12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1],
        [13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6],
        [ 1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2],
        [ 6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12]
    ],
    # S8
    [
        [13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
    ]
]


# =====================================================================
# FUNKSIONE NDIHMESE
# =====================================================================

def hex_to_bits(hex_str, length):
    """Konverton string hex ne liste bit-ash me gjatesi te dhene."""
    hex_str = hex_str.replace(" ", "").replace("0x", "")
    n = int(hex_str, 16)
    return [(n >> (length - 1 - i)) & 1 for i in range(length)]


def bits_to_hex(bits):
    """Konverton liste bit-ash ne string hex."""
    n = 0
    for b in bits:
        n = (n << 1) | b
    hex_len = (len(bits) + 3) // 4
    return format(n, f'0{hex_len}X')


def bits_to_str(bits):
    """Konverton liste bit-ash ne string te lexueshem (binar)."""
    return ''.join(str(b) for b in bits)


def permute(bits, table):
    """
    Aplikon nje permutacion (rirenditje) sipas tabeles se dhene.
    Tabela permban indekset (1-based ne DES standard).
    """
    return [bits[i - 1] for i in table]


def xor_bits(a, b):
    """XOR mes dy listave bit-ash me te njejten gjatesi."""
    return [x ^ y for x, y in zip(a, b)]


# =====================================================================
# FUNKSIONI f I DES-it (Figura 3.2)
# =====================================================================

def f_function(R, K, verbose=False):
    """
    Funksioni f i DES-it qe perdoret brenda nje round-i.

    Hapat (sipas Figures 3.2):
    1. Expansion E: R (32-bit) -> 48-bit
    2. XOR me SubKey K (48-bit)
    3. S-Boxet: 48-bit -> 32-bit (8 S-boxe x 6-bit hyrje -> 4-bit dalje)
    4. Permutacioni P: 32-bit -> 32-bit

    Argumentet:
        R: liste 32 bit-ash (gjysma e djathte)
        K: liste 48 bit-ash (SubKey, i dhene manualisht)

    Kthen: liste 32 bit-ash
    """
    # HAPI 1: Expansion E (32 -> 48 bit)
    expanded = permute(R, E_TABLE)
    if verbose:
        print(f"   [f] E(R)         = {bits_to_hex(expanded)} ({len(expanded)} bit)")

    # HAPI 2: XOR me SubKey K
    xored = xor_bits(expanded, K)
    if verbose:
        print(f"   [f] E(R) XOR K   = {bits_to_hex(xored)} ({len(xored)} bit)")

    # HAPI 3: Aplikimi i 8 S-Boxeve
    # Cdo S-Box merr 6 bit dhe nxjerr 4 bit
    sbox_output = []
    for i in range(8):
        # Merr 6 bit-ah per kete S-Box
        block = xored[i * 6:(i + 1) * 6]

        # Rreshti = bit-i i pare dhe i fundit (2 bit -> 0..3)
        row = (block[0] << 1) | block[5]

        # Kollona = 4 bit-at ne mes (4 bit -> 0..15)
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]

        # Vlera nga S-Box-i (4-bit)
        val = S_BOXES[i][row][col]

        # Konverto 4-bit-shin ne 4 bit
        sbox_output.extend([(val >> (3 - j)) & 1 for j in range(4)])

    if verbose:
        print(f"   [f] S-Box output = {bits_to_hex(sbox_output)} ({len(sbox_output)} bit)")

    # HAPI 4: Permutacioni P (32 -> 32 bit)
    result = permute(sbox_output, P_TABLE)
    if verbose:
        print(f"   [f] P(S-output)  = {bits_to_hex(result)} ({len(result)} bit)")

    return result


# =====================================================================
# NJE ROUND I DES-it (Figura 3.2)
# =====================================================================

def des_one_round(plaintext_bits, subkey_bits, use_ip=True, verbose=True):
    """
    Implementon NJE round te DES-it.

    Argumentet:
        plaintext_bits: 64 bit hyrje
        subkey_bits: 48 bit SubKey (jepet manualisht)
        use_ip: True -> aplikon IP dhe IP^-1; False -> vetem round-i
        verbose: True -> printon hapat e brendshem

    Kthen: 64 bit dalje
    """
    if len(plaintext_bits) != 64:
        raise ValueError(f"Plaintext must be 64 bits, not {len(plaintext_bits)}")
    if len(subkey_bits) != 48:
        raise ValueError(f"SubKey must be 48 bits, not {len(subkey_bits)}")

    if verbose:
        print("\n" + "=" * 60)
        print("   ONE-ROUND DES IMPLEMENTATION")
        print("=" * 60)
        print(f"Plaintext (64-bit)  : {bits_to_hex(plaintext_bits)}")
        print(f"SubKey K1 (48-bit)  : {bits_to_hex(subkey_bits)}")
        print(f"Initial Permutation : {'YES' if use_ip else 'NO'}")
        print("-" * 60)

    # HAPI 1: Permutacioni Fillestar IP (opsional)
    if use_ip:
        block = permute(plaintext_bits, IP)
        if verbose:
            print(f"After IP            : {bits_to_hex(block)}")
    else:
        block = plaintext_bits[:]
        if verbose:
            print("(IP skipped)")

    # HAPI 2: Ndarja ne L0 dhe R0
    L0 = block[:32]
    R0 = block[32:]
    if verbose:
        print(f"L0 (32-bit)         : {bits_to_hex(L0)}")
        print(f"R0 (32-bit)         : {bits_to_hex(R0)}")
        print("-" * 60)
        print("Function f(R0, K1):")

    # HAPI 3: Llogaritja e nje round-i:
    #   L1 = R0
    #   R1 = L0 XOR f(R0, K1)
    f_result = f_function(R0, subkey_bits, verbose=verbose)
    L1 = R0
    R1 = xor_bits(L0, f_result)

    if verbose:
        print("-" * 60)
        print(f"L1 = R0             : {bits_to_hex(L1)}")
        print(f"R1 = L0 XOR f(R0,K1): {bits_to_hex(R1)}")

    # HAPI 4: Bashkimi L1 || R1
    combined = L1 + R1
    if verbose:
        print(f"L1 || R1            : {bits_to_hex(combined)}")

    # HAPI 5: Permutacioni Final IP^-1 (opsional)
    if use_ip:
        # Ne DES standard, pas round-it te fundit behet "swap" (R || L) pastaj IP^-1.
        # Por meqe ne kemi vetem 1 round, kete swap-in nuk e bejme; aplikohet
        # vetem IP^-1 mbi (L1 || R1) per te plotesuar simetrine e figures 3.1.
        output = permute(combined, IP_INVERSE)
        if verbose:
            print(f"After IP^-1 (output): {bits_to_hex(output)}")
    else:
        output = combined

    if verbose:
        print("=" * 60)
        print(f"FINAL OUTPUT (64-bit): {bits_to_hex(output)}")
        print("=" * 60)

    return output


# =====================================================================
# NDERFAQJA E PERDORUESIT (CLI)
# =====================================================================

def parse_hex_input(prompt, expected_bits):
    """Lexon hyrje hex nga perdoruesi dhe e validon."""
    expected_hex_chars = expected_bits // 4
    while True:
        s = input(prompt).strip().replace(" ", "").replace("0x", "")
        if len(s) == 0:
            print("   Error: input cannot be empty.")
            continue
        try:
            int(s, 16)
        except ValueError:
            print(f"   Error: '{s}' is not a valid hex string.")
            continue
        if len(s) != expected_hex_chars:
            print(f"   Error: expected {expected_hex_chars} hex characters "
                  f"({expected_bits} bits), got {len(s)}.")
            continue
        return hex_to_bits(s, expected_bits)


def main_menu():
    """Menyja kryesore e aplikacionit."""
    print("\n" + "#" * 60)
    print("#  PROJECT III - DATA SECURITY                           #")
    print("#  Group 7: One-Round DES Implementation                 #")
    print("#  Reference: Internet Security (Man Young Rhee, 2003)   #")
    print("#" * 60)

    while True:
        print("\n--- MENU ---")
        print("1. Run one DES round (with IP and IP^-1)")
        print("2. Run one DES round (round only, no IP)")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "0":
            print("Goodbye!")
            break

        elif choice in ("1", "2"):
            use_ip = (choice == "1")
            print("\nEnter input in HEX format (no '0x', no spaces).")
            print("  Plaintext: 16 hex characters (64 bits)")
            print("  SubKey:    12 hex characters (48 bits)")
            print()
            try:
                pt = parse_hex_input("Plaintext (64-bit, e.g. 0123456789ABCDEF): ", 64)
                sk = parse_hex_input("SubKey K1 (48-bit, e.g. 1B02EFFC7072): ", 48)
                des_one_round(pt, sk, use_ip=use_ip, verbose=True)
            except ValueError as e:
                print(f"Error: {e}")

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main_menu()
