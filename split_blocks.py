def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """
    Split data into fixed-size blocks (default: 16 bytes).
    """
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]
