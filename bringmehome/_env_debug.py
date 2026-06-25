import os

def dump(key: str):
    val = os.getenv(key)
    return val

