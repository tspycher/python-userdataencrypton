'''
Created on Dec 19, 2012

@author: thospy
'''
import unittest
import time

from secureuser import SecureUser, WrongPasswordError

class EncryptionTest(unittest.TestCase):
    def setUp(self):
        pass
    
    def tearDown(self):
        pass
    
    def test_password_recovery_level1(self):
        password = "Pas$word"
        su = SecureUser(password)
        sessionKey = su.unlock(password)
        text = "This is secure"
        encrypted = su.encrypt(text, sessionKey)
        self.assertEqual(text, su.decrypt(encrypted, sessionKey), "Could not en/decrypt userdata")
        
        print "Restoring password"
        adminpassword = "adminpw"
        newPassword = "Pa$sword2"
        su.restore_user_password(newPassword, adminpassword)
        sessionKey = su.unlock(newPassword)
        self.assertEqual(text, su.decrypt(su.encrypt(text, sessionKey), sessionKey), "Could not en/decrypt userdata after password reset")
        self.assertEqual(text, su.decrypt(encrypted, sessionKey), "Could not en/decrypt userdata encrypted with privious key")
    
    def test_wrong_passwords(self):
        password = "Pas$word"
        su = SecureUser(password)
        text = "This text is secure"
        self.assertRaises(WrongPasswordError, su.raw_keys, "ThisPwi$Wrong")
        self.assertRaises(WrongPasswordError, su.unlock, "thisPasswordIsWrong")
        sessionKey = su.unlock(password)
        self.assertRaises(WrongPasswordError, su.encrypt, text, "1234567891234567")
        encrypted = su.encrypt(text, sessionKey)
        self.assertRaises(WrongPasswordError, su.decrypt, encrypted, "1234567891234567")
        decrypted = su.decrypt(encrypted, sessionKey)
        self.assertEqual(decrypted, text, "Decryption is not equal")
        self.assertRaises(WrongPasswordError, su.restore_user_password, "ThisPwI$new", "WrongAdminPassword")
        
    def test_password_recovery_level2(self):
        # Create an Admin User and get his keys
        admin = SecureUser("adminpw")
        keys = admin.raw_keys("adminpw")
        
        password = "Pas$word"
        su = SecureUser(password, 2, admin_public_key = keys['public_key'])
        sessionKey = su.unlock(password)
        text = "This is secure"
        encrypted = su.encrypt(text, sessionKey)
        self.assertEqual(text, su.decrypt(encrypted, sessionKey), "Could not en/decrypt userdata")
        
        print "Restoring password"
        adminpassword = "adminpw"
        newPassword = "Pa$sword2"
        su.restore_user_password(newPassword, admin_private_key = keys['private_key'])
        
        sessionKey = su.unlock(newPassword)
        self.assertEqual(text, su.decrypt(su.encrypt(text, sessionKey), sessionKey), "Could not en/decrypt userdata after password reset")
        self.assertEqual(text, su.decrypt(encrypted, sessionKey), "Could not en/decrypt userdata encrypted with privious key")
        
    def test_serialisation(self):
        password = "Pas$word"
        text = "Ich bin ein Test"
        
        su = SecureUser(password)
        sessionKey = su.unlock(password)
        su_serial = su.serialize()
        
        self.assertTrue(su_serial, "No serialized object gotten")
        self.assertEqual(text, su.decrypt(su.encrypt(text, sessionKey), sessionKey), "Could not en/decrypt userdata")
        su = None
        print "Serialisation done"
        suNew = SecureUser.unserialize(su_serial)
        sessionKeyNew = suNew.unlock(password)
        self.assertEqual(text, suNew.decrypt(suNew.encrypt(text, sessionKeyNew), sessionKeyNew), "Could not en/decrypt userdata afer serialisation")
        print "Deserialisation done"
        
    def test_encryption_performance(self):
        password = "Pas$word"
        su = SecureUser(password)
        sessionKey = su.unlock(password)
        self.assertTrue(su.public_key, "There is no publickey")
        self.assertTrue(su._private_key, "no private key")
        
        text = []
        for i in range(5000):
            text.append("X")
        text = "".join(text)
        
        messages = []
        origMessages = []
        numMessages = 200
        
        startTime = time.time()
        for i in range(numMessages):
            data = "%i -%s" % (i, text)
            origMessages.append(data)
            messages.append(su.encrypt(data, sessionKey))
        timeEncryption = time.time()
        
        print "Encryption took %f seconds" % (timeEncryption-startTime)
        for i in range(numMessages):
            messages[i] = su.decrypt(messages[i], sessionKey)
            self.assertEqual(messages[i], origMessages[i], "The message has changed during decryptiong")
        timeDecryption = time.time()

        print "Decryption took %f seconds" % (timeDecryption-timeEncryption)
        print "En- Decryption took %f seconds" % (timeDecryption-startTime)
        
        
        
        
        '''
        # Time without caching
        Encryption took 3.782162 seconds
        Decryption took 3.766210 seconds
        En- Decryption took 7.548372 seconds
        
        # Time with caching
        Encryption took 0.034477 seconds
        Decryption took 0.014020 seconds
        En- Decryption took 0.048497 seconds
        '''
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()