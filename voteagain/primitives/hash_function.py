"""
Helper functions to hash elements.
"""

import hashlib
from petlib.ec import Bn


def compute_challenge(transcript, p):
    """Compute challenge given transcript

    TODO: return something of the right size, l_c bits in the paper.
    TODO: use proper unique encoding of elements
    """

    m = hashlib.sha512()
    for element in transcript:
        try:
            m.update(element.export())
        except AttributeError:
            try:
                m.update(hex(element).encode())
            except:
                m.update(hex(element.vid).encode())
                m.update(hex(element.index).encode())
                m.update(hex(element.tag).encode())
                m.update(hex(element.vote).encode())
    hashed = m.hexdigest()

    return (Bn.from_hex(hashed)).mod(Bn.from_num(p))


def compute_challenge_poly(transcript, p):
    """
    Compute challenge given transcript
    """
    transcript = flatten(transcript)
    m = hashlib.sha512()
    for element in transcript:
        try:
            m.update(element.commitment.export())
        except AttributeError:
            try:
                m.update(hex(element.commitment).encode())
            except:
                m.update(element.commitment.hex().encode())

    hashed = m.hexdigest()

    return (Bn.from_hex(hashed)).mod(Bn.from_num(p))


def flatten(lst):
    return sum(([x] if not isinstance(x, list) else flatten(x) for x in lst), [])
