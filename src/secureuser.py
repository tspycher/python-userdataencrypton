from M2Crypto import RSA, X509, EVP, ASN1, m2, BIO
from Crypto.Cipher import AES
import base64
import random
import time
import pickle


class SecureUser(object):
    public_key = None
    _private_key = None      # symetrical encrypted private key.
    _private_key_rescue = None    # symetrical encrypted private key. For rescueing if the primary gets lost.
    
    _encrypted_symetrical_key = None               # used to encrypt all data. the key itself is encrypted with the asymetrical key
    
    _sym_blocksize = 32
    _sym_padding = '{'
    
    _symkey_cache_enabled = True
    _symkey_cache = None
    _symkey_cache_time = 0
    _symkey_cache_timeout = 2
    
    def __init__(self, userpassword):
        self._create_keymaterial(userpassword)
    
    def _create_keymaterial(self, userpassword):
        # Create 2048bit strong keypair and load them into a RSA object
        keys = RSA.gen_key(bits=2048, e=7)
        keyPair = BIO.MemoryBuffer()
        keys.save_key_bio(keyPair, None)
        rsa = RSA.load_key_bio(keyPair)
        
        # Create BIO to store the keys in it for further retreiving the raw keys
        pri_mem = BIO.MemoryBuffer()
        pub_mem = BIO.MemoryBuffer()
        rsa.save_key_bio(pri_mem, None)
        rsa.save_pub_key_bio(pub_mem)
        self.public_key = pub_mem.getvalue()

        # Get the private key and encrypt it 
        self._private_key = self._sym_encrypt(pri_mem.getvalue(), userpassword)
        #self._private_key_rescue = self._sym_encrypt(pri_mem.getvalue(), "adminpw")
        
        # Create the Symetricalkey for the encryption of user data. Key gets encrypted with the private key of the user
        self._encrypted_symetrical_key = self._async_encrypt(self._random_key(), userpassword)
    
    def encrypt(self, data, userpassword):
        '''
        Symmetrical encryption of userdata. Data can be as big as possible.
        '''
        key = self._sym_key(userpassword)
        return self._sym_encrypt(data, key)
    
    def decrypt(self, data, userpassword):
        '''
        Symmetrical Decryption of userdata
        '''
        key = self._sym_key(userpassword)
        return self._sym_decrypt(data, key)

    def _sym_key(self, userpassword):
        '''
        Returns the Symmetrical key of the user
        '''
        
        if self._symkey_cache and self._symkey_cache_enabled:
            if (time.time() - self._symkey_cache_time) >= self._symkey_cache_timeout:
                self._symkey_cache = None
                self._symkey_cache_time = None
                print "Resetting key"
            else:
                self._symkey_cache_time = time.time()
                return self._symkey_cache
            
        self._symkey_cache_time = time.time()
        self._symkey_cache = self._async_decrypt(self._encrypted_symetrical_key, userpassword)
        if not self._symkey_cache_enabled:
            x = self._symkey_cache
            self._symkey_cache = None
            return x
        return self._symkey_cache
    
    def _sym_encrypt(self, data, secret):
        '''
        Final symmetrical encryption of given data with AES256
        '''
        secret = secret + (self._sym_blocksize - len(secret) % self._sym_blocksize) * self._sym_padding
        cipher = AES.new(secret)
        data = data + (self._sym_blocksize - len(data) % self._sym_blocksize) * self._sym_padding
        return base64.b64encode(cipher.encrypt(data))
    
    def _sym_decrypt(self,data,secret):
        '''
        Final symmetrical decryption of given data with AES256
        '''
        secret = secret + (self._sym_blocksize - len(secret) % self._sym_blocksize) * self._sym_padding
        cipher = AES.new(secret)
        return cipher.decrypt(base64.b64decode(data)).rstrip(self._sym_padding)
    
    def _random_key(self, lenght = 32):
        '''
        Generates an random key of the given lenght
        '''
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+_$*%&)(=+<>^"
        pw = []
        for i in range(lenght-1):
            pw.append(chars[random.randint(0,len(chars)-1)])
        return "".join(pw)
    
    ## Asymetric
    def _rsa(self, userpassword):
        '''
        Gets the RSA Object
        '''
        return RSA.load_key_string("%s%s" % (self.public_key, self._sym_decrypt(self._private_key, userpassword)))
    
    def _async_encrypt(self, data, userpassword):
        '''
        Asymmetrical RSA Encryption of given data
        '''
        rsa = self._rsa(userpassword)
        return base64.b64encode(rsa.public_encrypt(data, 1))

    def _async_decrypt(self, data, userpassword):
        '''
        Asymmetrical RSA Decryption of given data
        '''
        rsa = self._rsa(userpassword)
        try:
            return rsa.private_decrypt(base64.b64decode(data), 1)
        except RSA.RSAError:
            self.logger.log.error("Could not decrypt")
            return str()

    def restore_user_password(self):
        pass
    
    def __getstate__(self):
        '''
        Makes sure that only allowed attributes getting serialized
        '''
        save_attributes = ['public_key', '_private_key','_private_key_rescue','_encrypted_symetrical_key']
        x = dict()
        for key ,value in self.__dict__.iteritems():
            if key in save_attributes:
                x[key] = value
        return x

    def serialize(self):
        '''
        Serializes this object. An serialized object can get transfered over any connection type like http, tcp etc.
        '''
        self._symkey_cache = None
        self._symkey_cache_time = 0
        return pickle.dumps(self)
    
    @staticmethod
    def unserialize(objectString):
        '''
        Static method for easy access the load method of pickle. Creates an object again from an serialized object.
        '''
        return pickle.loads(objectString)