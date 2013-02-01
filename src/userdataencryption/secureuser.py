from M2Crypto import RSA, X509, EVP, ASN1, m2, BIO
from Crypto.Cipher import AES
import base64
import random
import time
import pickle

class WrongPasswordError(Exception):
    '''
    Exception Class to handel wrong passwords
    '''
    
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class SecureUser(object):
    '''
    The SecureUser Class provides strong encryption support for userdata. It also provides the controll of the security level.
    Increasing the security level, decreases the ability to restore a forgotten password. Level 3 does not provide any possiblity
    of restoring a lost password. If this happens all userdata is lost.
    
    1. A new RSA Keypair for the user gets created.
    2. The Private Key gets symmetrical encrypted with password of the user. In security Level 1&2 the key gets additional encrypted as a rescue element
    3. A new 32Byte long symmetrical key gets created. This key gets used to encrypt all userdata
    4. The masterkey gets encrypted with the private key of the user 
    '''
    public_key = None                       #: The public key of this object
    security_level = 1                      #: security Level of the user: 1 = insecure, 2 = more secure, 3 = highes security
    
    _private_key = None                     #: symetrical encrypted private key.
    _private_key_rescue = None              #: symetrical encrypted private key. For rescueing if the primary gets lost.
    _encrypted_symetrical_key = None        #: used to encrypt all data. the key itself is encrypted with the asymetrical key
    
    _sym_blocksize = 32                     #: Symmetrical Blocksize
    _sym_padding = '{'                      #: Padding character for smaller blocksizes
        
    _session_key = None                     #: Symmetrical encrypted session key
    _session_key_time = None                #: The timestamp of the time the key has last used
    _session_key_timeout = 2                #: Timout in seconds after the session_key gets purged
    
    password = None                         #: contains the random password on newly created instances without any password provided
    
    def __init__(self, userpassword = None, level = 1, admin_public_key = None):
        self._create_keymaterial(userpassword, level, admin_public_key)
    
    def _create_keymaterial(self, userpassword, level = 1, admin_public_key = None):
        '''
        Initializes all the keymaterial for a new object
        '''
        if not userpassword:
            userpassword = self._random_key(8)
            self.password = userpassword
        
        self.security_level = level
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
        # The rescue key gets only created of a userlevel below three has been choosen
        p = pri_mem.getvalue()
        self._private_key = self._sym_encrypt(p, userpassword)
        if self.security_level < 3:
            if self.security_level <= 1:
                # symmetrical encryption of the rescue key
                self._private_key_rescue = self._sym_encrypt(p, "adminpw")
            else:
                # asymmetrical encryption of the recue key with the keypair of the admin
                x = RSA.load_pub_key_bio(BIO.MemoryBuffer(admin_public_key))
                chunksize = 245 #246 byte are too much for rsa encryption
                y = []
                for i in range((len(p)/chunksize)+1):
                    y.append(base64.b64encode( x.public_encrypt((p[i * chunksize:(i * chunksize)+chunksize]),1) ) )
                self._private_key_rescue = "\n".join(y)
        
        # Create the Symetricalkey for the encryption of user data. Key gets encrypted with the private key of the user
        self._encrypted_symetrical_key = self._async_encrypt(self._random_key(), userpassword)
    
    def unlock(self, userpassword):
        '''
        Unlocks the symmetrical master key with the password of the user and creates
        a new random session password which gets used to symmetrical encrypt the the master
        key for this session.
        '''
        session_password = self._random_key()
        self._session_key = self._sym_encrypt(self._sym_key(userpassword), session_password)
        self._session_key_time = time.time()
        return session_password
    
    def raw_keys(self, userpassword):
        '''
        Returns the raw key material
        '''
        try:
            return {"public_key":self.public_key,
                    "private_key":self._sym_decrypt(self._private_key, userpassword),
                    "symmetrical_key":self._sym_key(userpassword)}
        except:
            raise WrongPasswordError("Could not get keymaterial")
    
    def encrypt(self, data, session_password):
        '''
        Symmetrical encryption of userdata. Data can be as big as possible.
        '''
        key = self._key(session_password)
        return self._sym_encrypt(data, key)
    
    def decrypt(self, data, session_password):
        '''
        Symmetrical Decryption of userdata
        '''
        key = self._key(session_password)
        return self._sym_decrypt(data, key)
    
    def change_password(self, old_password, new_password):
        '''
        Changes the password of the user
        '''
        #key = self._key(session_password)
        private_key = self._sym_decrypt(self._private_key, old_password)
        self._private_key = self._sym_encrypt(private_key, new_password)
    
    def _key(self, session_password):
        '''
        Returns the Symmetrical key temporary encrypted with the session secret
        '''
        if (time.time() - self._session_key_time) >= self._session_key_timeout:
            return None
        self._session_key_time = time.time()
        return self._sym_decrypt(self._session_key, session_password)
    
    def _sym_key(self, userpassword):
        '''
        Returns the Symmetrical key of the user
        '''
        return self._async_decrypt(self._encrypted_symetrical_key, userpassword)
    
    def _sym_encrypt(self, data, secret):
        '''
        Final symmetrical encryption of given data with AES256
        '''
        cipher = self._cipher(secret)
        data = data + (self._sym_blocksize - len(data) % self._sym_blocksize) * self._sym_padding
        return base64.b64encode(cipher.encrypt(data))
    
    def _sym_decrypt(self,data,secret):
        '''
        Final symmetrical decryption of given data with AES256
        '''
        cipher = self._cipher(secret)
        return cipher.decrypt(base64.b64decode(data)).rstrip(self._sym_padding)
    
    def _cipher(self,secret):
        '''
        Gets an AES based cipher object
        '''
        try:
            secret = secret + (self._sym_blocksize - len(secret) % self._sym_blocksize) * self._sym_padding
            return AES.new(secret)
        except:
            raise WrongPasswordError("Could not create cipher")
        
    def _random_key(self, lenght = 32):
        '''
        Generates an random key of the given lenght
        '''
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+_$*%&)(=+<>^"
        pw = []
        for i in range(lenght-1):
            pw.append(chars[random.randint(0,len(chars)-1)])
            i
        return "".join(pw)
    
    ## Asymetric
    def _rsa(self, userpassword):
        '''
        Gets the RSA Object
        '''
        try:
            return RSA.load_key_string("%s%s" % (self.public_key, self._sym_decrypt(self._private_key, userpassword)))
        except:
            raise WrongPasswordError("Could not create RSA Object")
            
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

    def restore_user_password(self, newpassword, adminpassword = None, admin_private_key = None):
        '''
        Public method to recover a lost password.
        '''
        if self.security_level == 1:
            return self._restore_level1(newpassword, adminpassword)
        
        if self.security_level == 2 and admin_private_key:
            return self._restore_level2(newpassword, admin_private_key)
    
    def _restore_level1(self, newpassword, adminpassword):
        '''
        Restores a lost passwort of an user with security level 1
        The Rescue password is symmetrical encrypted
        '''
        x = self._sym_decrypt(self._private_key_rescue, adminpassword)
        try:
            RSA.load_key_string(x)
        except:
            raise WrongPasswordError("Could not restore Private Key with Admin Password")
        self._private_key = self._sym_encrypt(x, newpassword)
        return True

    def _restore_level2(self, newpassword, admin_private_key):
        '''
        Restores a lost password of an user with security level 2
        The Rescue password is asymmetrical encrypted with an admin key pair where the private key is external
        '''
        #print self._private_key_rescue
        rsa = RSA.load_key_string(admin_private_key)
        privateKey = []
        for x in self._private_key_rescue.splitlines():
            privateKey.append(rsa.private_decrypt(base64.b64decode(x), 1))
        #x = rsa.private_decrypt(base64.b64decode(self._private_key_rescue), 1)
        # print "".join(privateKey)
        #x = self._async_decrypt(self._private_key_rescue, admin_private_key)
        self._private_key = self._sym_encrypt("".join(privateKey), newpassword)
        return True

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