import hmac
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

prime256v1 = ec.SECP256R1()


def get_private_key(pem_location, password, generate=False):
    """
    Get private key from PEM file.
    :param pem_location: Location of PEM file.
    :param password: Password of PEM file in bytes.
    :param generate: if True, generate PEM file if not exists.
    :return: private key in ec.EllipticCurvePrivateKey
    """
    if not isinstance(password, bytes):
        raise TypeError('password must be bytes')
    try:
        private_key_pem = open(pem_location, 'rb').read()
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )
    except FileNotFoundError as e:
        if generate:
            pem = open(pem_location, 'wb')
            private_key = ec.generate_private_key(prime256v1, default_backend())
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
            pem.write(private_key_pem)
        else:
            raise e

    return private_key


def encode_public_key(public_key):
    """
    Encode public key to URL-safe Base64 format.
    :param public_key: instance of ec.EllipticCurvePublicKey
    :return: URL-safe Base64 encoded public key
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return urlsafe_b64encode(public_key.public_numbers().encode_point()).decode('utf-8')
    else:
        raise TypeError(public_key, 'must be an instance of EllipticCurvePublicKey')


def simple_hkdf(salt, ikm, info, length):
    """
    Simplified HMAC Key Derivation Function which supports up to 32 bytes long key
    :param salt: Cryptographic salt in bytes
    :param ikm: Initial keying material
    :param info: Structured data
    :param length: length of desired output key
    :return: the derived key.
    """
    if length > 32:
        raise ValueError('Cannot return keys of more than 32 bytes, %d requested' % length)
    key_hmac = hmac.new(salt, digestmod='sha256')
    key_hmac.update(ikm)
    key = key_hmac.digest()

    info_hmac = hmac.new(key, digestmod='sha256')
    info_hmac.update(info)
    info_hmac.update(b'\x01')
    return info_hmac.digest()[:length]


def hkdf(salt, ikm, info, length):
    """
    Wrapper for cryptography.hazmat.primitives.kdf.hkdf.HKDF
    :param salt: Cryptographic salt in bytes
    :param ikm: Initial keying material
    :param info: Structured data
    :param length: length of desired output key
    :return: the derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(ikm)


def create_info(type, client_public_key, server_public_key):
    if not isinstance(type, bytes):
        raise TypeError('type must be bytes')
    # The start index for each element within the buffer is:
    # value               | length | start    |
    # -----------------------------------------
    # 'Content-Encoding: '| 18     | 0        |
    # type                | len    | 18       |
    # nul byte            | 1      | 18 + len |
    # 'P-256'             | 5      | 19 + len |
    # nul byte            | 1      | 24 + len |
    # client key length   | 2      | 25 + len |
    # client key          | 65     | 27 + len |
    # server key length   | 2      | 92 + len |
    # server key          | 65     | 94 + len |
    # For the purposes of push encryption the length of the keys will
    # always be 65 bytes.

    # The string 'Content-Encoding: ' in utf-8
    info = b'Content-Encoding: '
    # Tye 'type' of the record, a utf-8 string
    info += type
    # null + 'P-256' (representing the EC being used) + null
    info += b'\x00P-256\x00'
    # The length of the client's public key as a 16-bit integer
    info += len(client_public_key).to_bytes(2, byteorder='big')
    # Actual client's public key
    info += client_public_key
    # The length of our public key
    info += len(server_public_key).to_bytes(2, byteorder='big')
    # Actual public key
    info += server_public_key

    return info


def dump_private_key(private_key):
    # DEBUG USE ONLY
    # It is represented as the base64url encoding of
    # the octet string representation of the private key value, as defined
    # in Section 2.3.7 of SEC1 [SEC1].
    private_key_value = private_key.private_numbers().private_value
    return urlsafe_b64encode(private_key_value.to_bytes(32, byteorder='big')).decode('utf-8')


def fill_padding(base64):
    missing_padding = len(base64) % 4
    if type(base64) == str:
        base64 += '=' * missing_padding
    elif type(base64) == bytes:
        base64 += b'=' * missing_padding
    else:
        raise TypeError('base64 must be an instance of str or bytes')

    return base64
