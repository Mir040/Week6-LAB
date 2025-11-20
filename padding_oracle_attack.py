def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """
    Perform a full padding oracle attack on multi-block ciphertext.
    """
    blocks = split_blocks(ciphertext)
    recovered = b""

    # Block 0 is IV → plaintext begins with block 1
    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks)-1}")
        p = decrypt_block(blocks[i - 1], blocks[i])
        recovered += p

    return recovered
