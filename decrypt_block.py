def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Recover the plaintext of target_block using the padding oracle attack.
    prev_block is the block before it (IV for block 1).
    """
    plaintext = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)
    fake = bytearray(prev_block)

    # Decrypt byte-by-byte from right to left
    for pad in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad

        # Fix previously solved bytes to enforce the correct padding
        for j in range(1, pad):
            fake[BLOCK_SIZE - j] = intermediate[BLOCK_SIZE - j] ^ pad

        # Try each possible byte value 0–255
        for guess in range(256):
            fake[pos] = guess
            test = bytes(fake) + target_block

            if padding_oracle(test):
                # Compute intermediate value (Dec(Ci))
                intermediate[pos] = guess ^ pad
                # Compute plaintext byte: P = I XOR C_(i-1)
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                break

    return bytes(plaintext)
