from django.test import TestCase
import bcrypt

# Create your tests here.

class TestBcrypt(TestCase):

    def setUp(self):
        print("Setting up")
    
    def test_bcrypt_happy(self):
        password = "maneesh"
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)

        self.assertEqual(bcrypt.checkpw(password, hashed), True)

    def test_bcrypt_failing(self):
        password = "maneesh"
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)

        self.assertEqual(bcrypt.checkpw("maneesh123", hashed), False)
    


