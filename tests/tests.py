import unittest
from app.crypto_utils import caesar_cipher, encrypt_text, decrypt_text, generate_key

class CryptoTests(unittest.TestCase):
    def test_caesar_cipher(self):
        self.assertEqual(caesar_cipher("Hello, World!", 3), "Khoor, Zruog!")
        self.assertEqual(caesar_cipher("Khoor, Zruog!", 3, encrypt=False), "Hello, World!")

    def test_fernet_encryption(self):
        key = generate_key()
        text = "This is a secret message."
        encrypted = encrypt_text(text, key)
        decrypted = decrypt_text(encrypted, key)
        self.assertEqual(text, decrypted)

if __name__ == '__main__':
    unittest.main()
