def unpad_and_decode(plaintext: bytes) -> str:
    """
    Remove PKCS#7 padding and decode to UTF-8 text.
    """
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    unpadded = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded.decode(errors="replace")
