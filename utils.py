import hmac
import hashlib
import struct
import datetime


RESPONSE_VERSION = HI_RESPONSE_VERSION = b'\x01'
ENCODING = 'utf-16le'


def concatenate(*args: str | bytes) -> bytes:
    """Chain arguments to one byte string.

    Returns:
        bytes: chain string
    """
    return b''.join(map(
        lambda x: x.encode('utf-16le') if isinstance(x, str) else x, args))


def to_unicode(string: str) -> str:
    """Convert string to unicode.

    Args:
        string (str): any utf-8 text

    Returns:
        str: unicode text
    """
    return ''.join(r'\u{:04X}'.format(ord(chr)) for chr in string)


def hmac_md5(key: str | bytes, value: str | bytes) -> bytes:
    """Hash string or bytes to md5 hash

    Args:
        key (str | bytes): key for md5 hash
        value (str | bytes): hashable value

    Returns:
        bytes: hmac md5 hash
    """
    key = key.encode(ENCODING) if isinstance(key, str) else key
    value = value.encode(ENCODING) if isinstance(value, str) else value
    return hmac.digest(key, value, 'md5')


def md4(text: str) -> bytes:
    """Hash string to md4 hash

    Args:
        string (str): any text

    Returns:
        bytes: md4 hash
    """
    return hashlib.new('md4', text.encode(ENCODING)).hexdigest()


def NTOWFv2(password: str, user: str, domain: str) -> bytes:
    """A one-way function (OWF) used to create a hash
    based on the user's password to generate a principal's secret key.

    Args:
        password (str): user's password
        user (str): username
        domain (str): domain name

    Returns:
        bytes: md5 hash key
    """
    return hmac_md5(
        md4(to_unicode(password)),
        to_unicode(user.upper() + domain.upper()),
    )


def get_timestamp() -> bytes:
    """Get little-endian 8 bytes current timestamp."""

    return struct.pack('<q', int(datetime.datetime.utcnow().timestamp()))


def create_ntlm_response(
    user: str,
    password: str,
    domain: str,
    client_challenge: bytes,
    server_challenge: bytes,
) -> bytes:
    """LMOWFv2 algorythm equals to NTOWFv2.

    Args:
        user (str): _description_
        password (str): _description_
        domain (str): _description_
        client_challenge (bytes): _description_
        server_challenge (bytes): _description_

    Returns:
        tuple[bytes, bytes, bytes]: nt_response, lm_response, proof_string
    """
    common_challenge = concatenate(server_challenge, client_challenge)
    key_nt = key_lm = NTOWFv2(password, user, domain)

    temp = concatenate(
        RESPONSE_VERSION,
        HI_RESPONSE_VERSION,
        bytearray(6),
        get_timestamp(),
        client_challenge,
        bytearray(4),
        domain,
        bytearray(4),
    )

    nt_proof_str = hmac_md5(key_nt, concatenate(server_challenge, temp))

    return (
        concatenate(nt_proof_str, temp),
        concatenate(hmac_md5(key_lm, common_challenge), client_challenge),
        nt_proof_str,
    )