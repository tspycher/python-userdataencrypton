from M2Crypto import RSA, X509, EVP, ASN1, m2, BIO
from Crypto.Cipher import AES
import base64
import random

class SecureUser(object):
    public_key = None
    _private_key = None      # symetrical encrypted private key.
    _private_key_rescue = None    # symetrical encrypted private key. For rescueing if the primary gets lost.
    
    _encrypted_symetrical_key = None               # used to encrypt all data. the key itself is encrypted with the asymetrical key
    
    def __init__(self, userpassword):
        self._create_keymaterial(userpassword)
    
    def _create_keymaterial(self, userpassword):
        keys = RSA.gen_key(bits=2048, e=7)
        keyPair = BIO.MemoryBuffer()
        keys.save_key_bio(keyPair, None)
        rsa = RSA.load_key_bio(keyPair)

        # Create memory buffers
        pri_mem = BIO.MemoryBuffer()
        pub_mem = BIO.MemoryBuffer()
        # Save keys to buffers
        rsa.save_key_bio(pri_mem, None)
        rsa.save_pub_key_bio(pub_mem)
        
        # Get keys 
        self.public_key = pub_mem.getvalue()
        private_key = pri_mem.getvalue()
        self._private_key = self._sync_encrypt(private_key, userpassword)
        self._private_key_rescue = self._sync_encrypt(private_key, "adminpw")
        
        # Create the Symetricalkey
        self._encrypted_symetrical_key = self._async_encrypt(self._random_key(), userpassword)
    
    def encrypt(self, data, userpassword):
        key = self._sym_key(userpassword)
        return self._sync_encrypt(data, key)
    
    def decrypt(self, data, userpassword):
        key = self._sym_key(userpassword)
        return self._sync_decrypt(data, key)

    def _sym_key(self, userpassword):
        return self._async_decrypt(self._encrypted_symetrical_key, userpassword)

    def _sync_encrypt(self, data, secret):
        blocksize = 32
        padding = '{'
        
        secret = secret + (blocksize - len(secret) % blocksize) * padding
        cipher = AES.new(secret)
        data = data + (blocksize - len(data) % blocksize) * padding
        return base64.b64encode(cipher.encrypt(data))
    
    def _sync_decrypt(self,data,secret):
        blocksize = 32
        padding = '{'
        
        secret = secret + (blocksize - len(secret) % blocksize) * padding
        cipher = AES.new(secret)
        return cipher.decrypt(base64.b64decode(data)).rstrip(padding)
    
    def _random_key(self, lenght = 32):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+_$*%&)(=+<>^"
        pw = []
        for i in range(lenght-1):
            pw.append(chars[random.randint(0,len(chars)-1)])
        return "".join(pw)
    
    ## Asymetric
    def _rsa(self, userpassword):
        return RSA.load_key_string("%s%s" % (self.public_key, self._sync_decrypt(self._private_key, userpassword)))
    
    def _async_encrypt(self, data, userpassword):
        rsa = self._rsa(userpassword)
        return base64.b64encode(rsa.public_encrypt(data, 1))

    def _async_decrypt(self, data, userpassword):
        rsa = self._rsa(userpassword)
        try:
            return rsa.private_decrypt(base64.b64decode(data), 1)
        except RSA.RSAError:
            self.logger.log.error("Could not decrypt")
            return str()

    def restore_user_password(self):
        pass