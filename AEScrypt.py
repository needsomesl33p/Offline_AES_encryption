from Crypto.Cipher import AES
import argparse


# MODE prefix will be needed e.g., AES.MODE_CBC
MODES = {
    "ECB": 1,
    "CBC": 2,
    "CFB": 3,
    "OFB": 5,
    "CTR": 6,
    "OPENPGP": 7,
    "CCM": 8,
    "EAX": 9,
    "SIV": 10,
    "GCM": 11,
    "OCB": 12
}


class AESEncryptor(object):
    '''
    Key size: 128 bits, 192 bits, 256 bites => 16 bytes, 24 bytes, 32 bytes
    Rounds:   10,        12        14
    Block size: 128 bits (fixed)
    '''
    def __init__(self, IV: str, key: str, plaintext_data: str, modes_of_operation: int, encoding: str):
        self.IV = IV
        self.key = key
        self.plaintext_data = plaintext_data
        self.modes_of_operation = modes_of_operation
        self.encodig = encoding

    def encrypt(self) -> str:
        AES_cipher = AES.new(self.key, self.modes_of_operation, self.IV)
        decrypted_data = AES_cipher.encrypt(self.encrypted_data)
        return self.unbox_PKCS5Padding(decrypted_data)


class AESDecryptor(object):

    def __init__(self, IV: str, key: str, encrypted_data: str, modes_of_operation: int, encoding: str):
        self.IV = IV
        self.key = key
        self.plaintext_data = plaintext_data
        self.modes_of_operation = modes_of_operation
        self.encodig = encoding

    def decrypt(self) -> str:
        AES_cipher = AES.new(self.key, self.modes_of_operation, self.IV)
        decrypted_data = AES_cipher.decrypt(self.encrypted_data)
        return self.unbox_PKCS5Padding(decrypted_data)


def parse():
    parser = argparse.ArgumentParser(prog="AES_decryptor", description="Decrypts AES encrypted ciphertext.")
    parser.add_argument('-i', '--iv', help="Base64 encoded format of the IV", required=True)
    parser.add_argument('-k', '--key', help="Base64 encoded format of the key", required=True)
    parser.add_argument('-c', '--ciphertext', help="Base64 encoded format of the ciphertext", required=True)
    return parser.parse_args()


def main():
    args = parse()
    AES_decryptor = AESDecryptor(args.iv, args.key, args.ciphertext, AES.MODE_CBC)
    AES_decryptor.base64_decode()
    plaintext = AES_decryptor.decrypt()

    print(f"The decrypted text is: {plaintext.decode()}")


if __name__ == "__main__":
    main()
