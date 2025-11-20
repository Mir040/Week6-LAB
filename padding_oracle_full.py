from binascii import unhexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
KEY = b"this_is_16_bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def padding_oracle(ciphertext: bytes) -> bool:
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    plaintext = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)
    fake = bytearray(prev_block)

    for pad in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad
        for j in range(1, pad):
            fake[BLOCK_SIZE - j] = intermediate[BLOCK_SIZE - j] ^ pad
        for guess in range(256):
            fake[pos] = guess
            test_cipher = bytes(fake) + target_block
            if padding_oracle(test_cipher):
                intermediate[pos] = guess ^ pad
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                break

    return bytes(plaintext)

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext)
    recovered = b""
    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks)-1}")
        p = decrypt_block(blocks[i - 1], blocks[i])
        recovered += p
    return recovered

def unpad_and_decode(plaintext: bytes) -> str:
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    unpadded = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded.decode(errors="replace")

if __name__ == "__main__":
    ciphertext = unhexlify(CIPHERTEXT_HEX)
    print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
    print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")
    recovered = padding_oracle_attack(ciphertext)
    print("\n[+] Decryption complete!")
    print(f" Recovered plaintext (raw bytes): {recovered}")
    print(f" Hex: {recovered.hex()}")
    decoded = unpad_and_decode(recovered)
    print("\n Final plaintext:")
    print(decoded)
