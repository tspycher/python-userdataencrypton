'''
Created on Dec 19, 2012

@author: thospy
'''
import unittest
import time

from secureuser import SecureUser

class EncryptionTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_serialisation(self):
        password = "Pas$word"
        text = "Ich bin ein Test"
        
        su = SecureUser(password)
        su_serial = su.serialize()
        
        self.assertTrue(su_serial, "No serialized object gotten")
        self.assertEqual(text, su.decrypt(su.encrypt(text, password), password), "Could not en/decrypt userdata")
        su = None
        
        suNew = SecureUser.unserialize(su_serial)
        self.assertEqual(text, suNew.decrypt(suNew.encrypt(text, password), password), "Could not en/decrypt userdata afer serialisation")
        
    def test_createProduct(self):
        password = "Pas$word"
        su = SecureUser(password)
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
            messages.append(su.encrypt(data, password))
        timeEncryption = time.time()
        
        print "Encryption took %f seconds" % (timeEncryption-startTime)
        for i in range(numMessages):
            messages[i] = su.decrypt(messages[i], password)
            self.assertEqual(messages[i], origMessages[i], "The message has changed during decryptiong")
        timeDecryption = time.time()

        print "Decryption took %f seconds" % (timeDecryption-timeEncryption)
        print "En- Decryption took %f seconds" % (timeDecryption-startTime)
        
        
        
        
        '''
        # Time with caching
        Encryption took 3.782162 seconds
        Decryption took 3.766210 seconds
        En- Decryption took 7.548372 seconds
        
        # Time without caching
        Encryption took 0.034477 seconds
        Decryption took 0.014020 seconds
        En- Decryption took 0.048497 seconds
        '''
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()