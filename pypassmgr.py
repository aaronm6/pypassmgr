#!/usr/bin/env python3

# Some changed text from dev folder in dev branch

import os, re, sys, signal
import base64, json, argparse, yaml
from urllib import request as req
from getpass import getpass
from pydoc import pipepager as pp
from subprocess import call
from datetime import datetime
from randomart import randomart
from urwid_routines import (
    dual_editor,
    labels_menu,
    display_labels_and_cipher,
    display_labels_only
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_der_private_key,
    load_der_public_key
)

window_cols, window_rows = os.get_terminal_size(0)

# define a signal handler and register, to capture ctrl-c gracefully
def signal_handler(sig, frame):
    print('Action terminated.')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

class color:
    PURPLE     = '\033[95m'
    CYAN       = '\033[96m'
    DARKCYAN   = '\033[36m'
    BLUE       = '\033[94m'
    BLUE_BG    = '\033[104m'
    BLACK      = '\x1B[30m'
    GREEN      = '\033[92m'
    YELLOW     = '\033[93m'
    YELLOW_BG  = '\x1B[43m'
    RED_BG     = '\033[101m'
    RED        = '\033[91m'
    GRAY       = '\033[90m'
    GRAY_BG    = '\033[100m'
    DARKRED    = '\033[31m'
    DARKRED_BG = '\033[41m'
    BOLD       = '\033[1m'
    UNDERLINE  = '\033[4m'
    INVERSE    = '\x1B[7m'
    END        = '\033[0m'

class _aes256cbc:
    def __init__(self):
        self.reset()
    def reset(self):
        self.salt   = None
        self.aesKey = None
        self.aesIV  = None
    def _gen_salt(self, numBytes):
        self.salt = os.urandom(numBytes)
    def _gen_keyiv_from_password(self, password):
        assert self.salt is not None, \
            "We must have salt before we can derive a key from a password"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=48,
            salt=self.salt,
            iterations=100000,
            backend=default_backend())
        kdf_md = kdf.derive(password)
        self.aesKey = kdf_md[:32]
        self.aesIV  = kdf_md[32:]
    def _gen_keyiv_from_urandom(self):
        self.aesKey = os.urandom(32)
        self.aesIV  = os.urandom(16)
    def set_keyiv(self, aesKey, aesIV):
        self.aesKey = aesKey
        self.aesIV  = aesIV
    def encrypt_plainBytes(self):
        assert self.aesKey is not None, "aes key must be defined"
        assert self.aesIV is not None, "cbc IV must be defined"
        cipher = Cipher(
            algorithms.AES(self.aesKey), 
            modes.CBC(self.aesIV),
            backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        msg_padded = padder.update(self.plntxt) + padder.finalize()
        self.cipherTxt = encryptor.update(msg_padded) + encryptor.finalize()
    def decrypt_cipherBytes(self):
        cipher = Cipher(
            algorithms.AES(self.aesKey), 
            modes.CBC(self.aesIV),
            backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            plntxt_padded = decryptor.update(self.cipherTxt) + decryptor.finalize()
            self.plntxt   = unpadder.update(plntxt_padded) + unpadder.finalize()
        except:
            print("Bad decrypt")
            self.plntxt = b''
    def set_cipherBytes(self, cipherBytes):
        self.cipherTxt = cipherBytes
    def set_plaintext(self, plaintext):
        self.plntxt = plaintext
    def encrypt_for_backup(self, plaintext, password):
        self._gen_salt(8)
        self._gen_keyiv_from_password(password)
        self.set_plaintext(plaintext)
        self.encrypt_plainBytes()
        outputBytes = b'Salted__' + self.salt + self.cipherTxt
        return outputBytes
    def decrypt_from_backup(self, ciphertext, password):
        self.salt = ciphertext[8:16]
        self.set_cipherBytes(ciphertext[16:])
        self._gen_keyiv_from_password(password)
        self.decrypt_cipherBytes()
        return self.plntxt
    def encrypt_for_rsaprivkey(self, plaintext, password):
        self._gen_salt(64)
        self._gen_keyiv_from_password(password)
        self.set_plaintext(plaintext)
        self.encrypt_plainBytes()
        outputBytes = bytes([len(self.salt)]) + self.salt + self.cipherTxt
        outputBytes = base64.b64encode(outputBytes)
        outputStr = outputBytes.decode()
        return outputStr
    def decrypt_rsaprivkey(self, b64cipherbytes, password):
        cipherbytes = base64.b64decode(b64cipherbytes)
        salt_length = cipherbytes[0]
        self.salt = cipherbytes[1:(salt_length+1)]
        self.set_cipherBytes(cipherbytes[(salt_length+1):])
        self._gen_keyiv_from_password(password)
        self.decrypt_cipherBytes()
        return self.plntxt

#pathtothisfile = os.path.split(__file__)[0] + '/'
#pathtothisfile = os.path.dirname(__file__) + '/'
pathtothisfile = f'{os.path.dirname(__file__)}/'

def ask_file(message, default=''):
    """
    Ask the user for a file (absolute path), provide them with a default if they
    just hit <enter>, expand the '~'.  Return the given default if nothing is entered.
    """
    if default:
        default_file_label = f'({default})'
    else:
        default_file_label = ''
    #default_file = os.path.expanduser(default)
    file_name = input(f"{message} {default_file_label}: ")
    if not file_name:
        file_name = default
    return os.path.expanduser(file_name)

class ManagerClass:
    #defaultDir = os.path.expanduser("~/.pypassmgr/")
    print("TEMPORARY DATABASE DIRECTORY FOR DEV")
    defaultDir = os.path.expanduser("~/.pypassmgr_dev/")
    defaultName = defaultDir + '.passwords_db'
    defaultBUfname = defaultDir + ".backup"
    yaml_cfg_file = pathtothisfile + ".config.yml"
    
    #def __init__(self, db_file_name=None, backup_file_name=None):
    def __init__(self, override_db_default='default'):
        self.code_version = 'v1.2'
        self.pws = []
        self.privK_bytes     = None
        self.privK           = None
        self.pubK_bytes      = None
        self.pubK            = None
        self.file_exist      = False
        self.RSA_fingerprint = None
        self.RSA_randomart   = None
        self.version         = self.code_version
        self.db_url          = ''
        self.db_file_name    = ''
        self.db_default      = ''
        self.version         = self.code_version
        f_yaml_exists = True if os.path.isfile(self.yaml_cfg_file) else False
        json_load = None
        if f_yaml_exists:
            with open(self.yaml_cfg_file,'r') as ff:
                cfg = yaml.safe_load(ff)
            # If only a remote URL is given for the [read-only] database, this is used
            # If only a local filename (including path) is given for the [read-write] database, this is used
            # If both a URL and a local filename are given, the URL is used and the local file is ignored
            required_fields = ('DB_URL', 'DB_FILENAME', 'DEFAULT')
            if all([rr in cfg for rr in required_fields]):
                self.db_url = cfg['DB_URL']
                self.db_file_name = cfg['DB_FILENAME']
                self.db_dir_name = os.path.dirname(self.db_file_name)
                self.db_default = cfg['DEFAULT']
            else:
                print("Config file missing information. Please run setup again")
            if os.path.isfile(self.db_file_name):
                self.file_exist = True
            if (self.db_default.lower() == 'remote') or (override_db_default=='remote'):
                try:
                    self._load_remote()
                    #with req.urlopen(self.db_url) as resp:
                    #    json_load = json.load(resp)
                except:
                    print("Default db is set to 'remote', but the remote URL either doesn't exist")
                    print("or doesn't work. Run setup to fix. Switching to local db.")
                    self.db_default = 'local'
            if (self.db_default.lower() == 'local') or (override_db_default=='local'):
                try:
                    self._load_local()
                    #with open(self.db_file_name) as ff:
                    #    json_load = json.load(ff)
                except:
                    print("Local db failed to load. Run setup again to fix.")
            if self.db_default.lower() not in ('local','remote'):
                print("Default db is not defined.  Run setup to fix.")
        """
        if json_load:
            self._set_vars_from_json(json_load)
            
            self.pws         = json_load[2]
            self.privK_bytes = json_load[1][0] 
            self.privK       = None # don't decrypt privK ebytes unless needed
            self.pubK_bytes  = base64.b64decode(json_load[1][1])
            self.version     = json_load[0]
            del json_load
            self.pubK        = load_der_public_key(
                                    self.pubK_bytes, 
                                    default_backend())
            self._getFingerprint()
        """
    
    def _set_vars_from_json(self, jload):
        if jload is None:
            raise ValueError("Database loading failed")
        self.pws         = jload[2]
        self.privK_bytes = jload[1][0] 
        self.privK       = None # don't decrypt privK ebytes unless needed
        self.pubK_bytes  = base64.b64decode(jload[1][1])
        self.version     = jload[0]
        del json_load
        self.pubK        = load_der_public_key(
                                self.pubK_bytes, 
                                default_backend())
        self._getFingerprint()
    
    def _load_remote(self):
        json_load = None
        #if self.db_default != 'remote':
        try:
            with req.urlopen(self.db_url) as resp:
                json_load = json.load(resp)
        except:
            print("Reading remote data base failed.")
        self._set_vars_from_json(json_load)
    def _load_local(self):
        json_load = None
        #if self.db_dfault != 'local':
        if self.file_exist:
            try:
                with open(self.db_file_name) as ff:
                    json_load = json.load(ff)
            except:
                print("Reading local data base failed.")
        
    def setup(self):
        # ask_file(message, default='')
        remote_url = ask_file("Enter URL of remote password db or enter for default",
            default=self.db_url if self.db_url else '')
        
        local_file = ask_file("Enter filename for local password db or enter for default",
            default=self.db_file_name if self.db_file_name else self.defaultName)
        default_db = ask_file("Default db to use ('local'/'remote')",
            default=self.db_default if self.db_default else "local")
        if default_db.lower() not in ('local','remote'):
            print("Options are 'local' or 'remote'. Please run setup again")
        cfg = {
            "DB_URL": remote_url,
            "DB_FILENAME": local_file,
            "DEFAULT":default_db}
        with open(self.yaml_cfg_file,'w') as ff:
            yaml.safe_dump(cfg, ff)
        
        self.db_url = remote_url
        self.db_file_name = local_file
        self.db_dir_name = os.path.dirname(local_file)
        self.db_default = default_db
        
        print("Setup complete.")
    
    def _get_password(self, 
                      message='Password: ', 
                      confirm=False, 
                      message_confirm='Confirm password: '):
        """
        Prompt the user for a password with a secure prompt.
        kwarg "confirm" specifies whether or not the user should be 
              asked to confirm the password.  False (default) means 
              no confirmation, True means confirmation will be 
              required.
        kwarg "message" is the message that will prompt the user 
              before input.
        kwarg "message_confirm", if "confirm=True", will give the 
              message upon confirmation.
        """
        pwtxt = getpass(message)
        if confirm:
            pwconf = getpass(message_confirm)
            if pwtxt != pwconf:
                sys.tracebacklimit = 0
                raise ValueError("Password confirmation failed.")
        self._pw_bytes = pwtxt.encode()
    
    def createKeys(self):
        if not self.file_exist:
            print("Creating RSA key pair...")
            self.privK = asymmetric.rsa.generate_private_key(
                public_exponent=65537, 
                key_size=4096, 
                backend=default_backend())
            self.pubK = self.privK.public_key()
            self._encrypt_privK()
            self.pubK_bytes = self.pubK.public_bytes(
                Encoding.DER, 
                PublicFormat.SubjectPublicKeyInfo)
            self._getFingerprint()
            self.display_fingerprint()
        else:
            print("Password-manager file already exists.")
    
    def _getFingerprint(self):
        if not self.pubK:
            self.createKeys()
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(self.pubK_bytes)
        fingerprint_bytes = digest.finalize()
        self.RSA_fingerprint = fingerprint_bytes.hex()
        self.RSA_randomart = randomart(fingerprint_bytes, 
            keyname='RSA 4096', 
            hashname='SHA256',
            dims=(35,11))
    
    def display_fingerprint(self):
        if self.pubK_bytes is None:
            print("No RSA key exists yet")
        else:
            if (self.RSA_fingerprint is None) or (self.RSA_randomart is None):
                self._getFingerprint()
            print("RSA fingerprint is:")
            print(" SHA256:{:s}".format(self.RSA_fingerprint))
            print(self.RSA_randomart)
    
    def _decrypt_privK(self, message='Password: '):
        self._get_password(message=message)
        sys.tracebacklimit = 0
        aesDecrypt = _aes256cbc()
        privKbytes_unenc = aesDecrypt.decrypt_rsaprivkey(
            self.privK_bytes.encode(), self._pw_bytes)
        self.privK = load_der_private_key(
            privKbytes_unenc, 
            None, 
            backend=default_backend())
    
    def _encrypt_privK(
        self, 
        message="New password: ", 
        message_confirm="Confirm new password: ", 
        confirm=True):
        self._get_password(
            message=message,
            confirm=confirm,
            message_confirm=message_confirm)
        privK_bytes_no_enc = self.privK.private_bytes(
            Encoding.DER, 
            PrivateFormat.PKCS8, 
            NoEncryption())
        aesEncrypt = _aes256cbc()
        self.privK_bytes = aesEncrypt.encrypt_for_rsaprivkey(
            privK_bytes_no_enc, 
            self._pw_bytes)
    
    def reset_password(self):
        """
        NOTE: THE RSA KEYS DON'T CHANGE WITH THIS, ONLY THE PASSWORD 
              USED TO ENCRYPT THE PRIVATE KEY!!
        """
        self._decrypt_privK(message="Old password: ")
        self._encrypt_privK(message="Enter new password: ",
            message_confirm="Confirm new password: ", confirm=True)
    
    def reset_rsaKeys(self):
        """
        Regenerate an RSA key pair, and re-encrypt all the passwords 
        with the new key.
        """
        tempPWS = [[iLabel, self._decryptAESkeyiv(iKey), iPW] 
            for iLabel, iKey, iPW in self.pws]
        self.file_exist = False
        self.createKeys()
        self.pws = [[iLabel, self._encryptAESkeyiv(*iKey), iPW] 
            for iLabel, iKey, iPW in tempPWS]
    
    def _reset_aesKey(self, idx_pws):
        """
        Regenerate the AES keys for the entry identified with the input
        'idx_pws'.
        """
        if not isinstance(idx_pws, int):
            raise TypeError("Input 'idx_pws' must be an int.")
        if (idx_pws < 0) or (idx_pws >= len(self.pws)):
            raise IndexError("Input 'idx_pws' must have a value that " + \
                "is a valid index")
        iLabel, iaesKeyiv_enc, iPW_enc = self.pws[idx_pws]
        aesKey_old, aesIV_old = self._decryptAESkeyiv(iaesKeyiv_enc)
        aesObj = _aes256cbc()
        aesObj.set_keyiv(aesKey_old, aesIV_old)
        iPW_dec = self._decryptText(iPW_enc, aesObj)
        aesObj._gen_keyiv_from_urandom()
        iPW_enc_new = self._encryptText(iPW_dec, aesObj)
        iaesKeyiv_enc_new = self._encryptAESkeyiv(aesObj.aesKey, aesObj.aesIV)
        self.pws[idx_pws] = [iLabel, iaesKeyiv_enc_new, iPW_enc_new]
    
    def reset_all_aesKeys(self):
        for k in range(len(self.pws)):
            self._reset_aesKey(k)
    
    def _encryptText(self, msg, aesObj):
        """
        Take an input msg (as type str) and encrypt it using the public
        key.  Encrypted message is returned in base64 encoding as a str
        object.
        """
        aesObj.set_plaintext(msg.encode())
        aesObj.encrypt_plainBytes()
        msg_encrypted_str = base64.b64encode(aesObj.cipherTxt).decode()
        return msg_encrypted_str
    def _encryptAESkeyiv(self, aesKey, aesIV):
        padder = asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(hashes.SHA512()), 
            algorithm=hashes.SHA512(),
            label=None)
        key_enc_bytes = self.pubK.encrypt(aesKey+aesIV, padder)
        key_enc_b64str = base64.b64encode(key_enc_bytes).decode()
        return key_enc_b64str
    def _decryptText(self, msg_encrypted_str, aesObj):
        """
        Take an encrypted message, represented as a str object with 
        base64 encoding, and use the private rsa key to decrypt it.
        Input 'aesObj' must only have its (unencrypted) key and iv
        defined.
        """
        if not self.privK:
            self._decrypt_privK()
        msg_encrypted_bytes = base64.b64decode(msg_encrypted_str)
        aesObj.set_cipherBytes(msg_encrypted_bytes)
        aesObj.decrypt_cipherBytes()
        msg_decrypted = aesObj.plntxt.decode()
        return msg_decrypted
    def _decryptAESkeyiv(self, aeskeyiv_enc_b64str):
        if not self.privK:
            self._decrypt_privK()
        aeskeyiv_enc_bytes = base64.b64decode(aeskeyiv_enc_b64str)
        padder = asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None)
        keyiv_dec = self.privK.decrypt(aeskeyiv_enc_bytes, padder)
        aesKey = keyiv_dec[:32]
        aesIV  = keyiv_dec[32:]
        return aesKey, aesIV
    def add_entry(self):
        """
        No inputs (yet?).  User is directed to an editor, prompted to 
        enter key info, and then pw info.
        """
        if not self.file_exist:
            print("Password-manager file does not exist; creating RSA " + \
                "key pair...")
            self.createKeys()
        
        aesObj = _aes256cbc()
        aesObj._gen_keyiv_from_urandom()
        key_enc_b64str = self._encryptAESkeyiv(aesObj.aesKey, aesObj.aesIV)
        e_stat, new_key, newPW = dual_editor()
        newRev = '1'
        newTS_txt = str(datetime.now().timestamp())
        newPW_enc = self._encryptText(newPW, aesObj)
        newTS_enc = self._encryptText(','.join([newRev,newTS_txt]), aesObj)
        if new_key:
            if e_stat == 0:
                self.pws.append([new_key, key_enc_b64str, newPW_enc, newTS_enc])
            else:
                print("Action canceled")
        else:
            print("Key text must not be empty.")
    def edit_entry(self, searchString=''):
        if self.file_exist:
            idx_list = []
            entry_list = []
            for k, entry in enumerate(self.pws):
                if re.search(searchString, entry[0], re.IGNORECASE):
                    idx_list.append(k)
                    entry_list.append(entry[0])
            idx_editentry = labels_menu(entry_list, 
                user_message='SELECT ENTRY')
            if idx_editentry is not None:
                oldLabelText    = self.pws[idx_list[idx_editentry]][0]
                oldAESkeyiv_enc = self.pws[idx_list[idx_editentry]][1]
                oldPWtext_enc   = self.pws[idx_list[idx_editentry]][2]
                if len(self.pws[idx_list[idx_editentry]]) > 3:
                    oldTS_enc   = self.pws[idx_list[idx_editentry]][3]
                else:
                    oldTS_enc = None
                oldAESobj = _aes256cbc()
                oldAESobj.set_keyiv(*self._decryptAESkeyiv(oldAESkeyiv_enc))
                
                oldPWtext = self._decryptText(oldPWtext_enc, oldAESobj)
                if oldTS_enc:
                    newRev = int(self._decryptText(oldTS_enc, oldAESobj).split(',')[0]) + 1
                else:
                    newRev = 1
                newRev = str(newRev)
                newTS_plaintxt = str(datetime.now().timestamp())
                e_stat, newLabelText, newPWtext = dual_editor(
                    oldLabelText, oldPWtext)
                if newLabelText:
                    if (e_stat == 0):
                        newAESobj = _aes256cbc()
                        newAESobj._gen_keyiv_from_urandom()
                        key_enc_b64str = \
                            self._encryptAESkeyiv(newAESobj.aesKey, 
                                                  newAESobj.aesIV)
                        newPWtext_enc = \
                            self._encryptText(newPWtext, newAESobj)
                        newTS_enc = self._encryptText(','.join([newRev,newTS_plaintxt]), newAESobj)
                        self.pws[idx_list[idx_editentry]][0] = newLabelText
                        self.pws[idx_list[idx_editentry]][1] = key_enc_b64str
                        self.pws[idx_list[idx_editentry]][2] = newPWtext_enc
                        if int(newRev) > 1:
                            self.pws[idx_list[idx_editentry]][3] = newTS_enc
                        else:
                            self.pws[idx_list[idx_editentry]].append(newTS_enc)
                    else:
                        print("\nEntry edit canceled.\n")
                else:
                    print(" text must not be empty")
            else:
                print("\nSelection canceled.\n")
        else:
            print("Password manager file does not exist.  Use -h for help")
    
    def delete_entry(self, searchString=''):
        """
        User is prompted for a search string, if none given at function
        call.  A list is shown and the user is asked to select a key to 
        delete.
        """
        if self.file_exist:
            idx_list = []
            entry_list = []
            for k, entry in enumerate(self.pws):
                if re.search(searchString, entry[0], re.IGNORECASE):
                    idx_list.append(k)
                    entry_list.append(entry[0])
            idx_delentry = labels_menu(entry_list, 
                user_message='SELECT ENTRY')
            if idx_delentry is not None:
                flag_confirm = input("Delete entry: {:s} ? [y/n]: ".format(
                    self.pws[idx_list[idx_delentry]][0]))
                if flag_confirm in ('n','N'):
                    print("Deletion cancelled; nothing deleted")
                elif flag_confirm in ('y','Y'):
                    entryLabel = self.pws[idx_list[idx_delentry]][0]
                    del self.pws[idx_list[idx_delentry]]
                    print("key: '{:s}' deleted".format(entryLabel))
                else:
                    print("Unable to understand response; please try again")
            else:
                print("\nSelection canceled.\n")
        else:
            print("Password manager file does not exist.  Use -h for help")
    def entry_search(self, searchString=''):
        """
        User privides a search string, if none given at function call.
        This search string is compared against the *labels* of the 
        entries only.  A list is shown and the user is asked to select
        an entry, whose password info is then shown.
        """
        if self.file_exist:
            idx_list = []
            for k, entry in enumerate(self.pws):
                if re.search(searchString, entry[0], re.IGNORECASE):
                    idx_list.append(k)
            self._displayLabelPW(idx_list)
        else:
            print("Password manager file does not exist.  Use -h for help")
    def password_search(self, searchString=''):
        """
        This functions similarly to 'entry_search' (the default search
        method), but instead the search is performed over the encrypted
        parts of each entry.
        """
        if self.file_exist:
            idx_list = []
            aesObj = _aes256cbc()
            for k, entry in enumerate(self.pws):
                aesObj.set_keyiv(*self._decryptAESkeyiv(entry[1]))
                if re.search(searchString, self._decryptText(entry[2],aesObj)):
                    idx_list.append(k)
            self._displayLabelPW(idx_list)
        else:
            print("Password manager file does not exist.  Use -h for help")
    def disp_top(self,N):
        if N < 0:
            raise ValueError("Cannot display a negative number of entries.")
        M = min(N, len(self.pws))
        self._displayLabelPW(list(range(M)))
    def disp_bottom(self,N):
        if N < 0:
            raise ValueError("Cannot display a negative number of entries.")
        M = min(N, len(self.pws))
        self._displayLabelPW(list(range(len(self.pws)-M, len(self.pws))))
    def _displayLabelPW(self, idx_list):
        """
        Displays the labels and the decrypted password text
        """
        aesObj = _aes256cbc()
        labelList = [self.pws[k][0].strip() for k in idx_list]
        pwList = []
        ts_str = []
        for k0, idx in enumerate(idx_list):
            aesObj.set_keyiv(*self._decryptAESkeyiv(self.pws[idx][1]))
            pwList.append(self._decryptText(self.pws[idx][2], aesObj))
            if len(self.pws[idx]) > 3:
                ts_txt = self._decryptText(self.pws[idx][3], aesObj)
                ts_rev_txt = ts_txt.split(',')[0]
                ts_fl = float(ts_txt.split(',')[1])
                ts_str.append(f'[r{ts_rev_txt}: {datetime.fromtimestamp(ts_fl).ctime()}]')
            else:
                ts_str.append('[no timestamp for this entry]')
        label_ts_list = [f'{item0}\n{item1}' for item0, item1 in zip(labelList, ts_str)]
        display_labels_and_cipher(label_ts_list, pwList)
    
    def _displayLabelOnly(self, entries, postambletext=None):
        display_labels_only(entries)
    
    def displayAllLabels(self):
        entry_list = [item[0] for item in self.pws]
        self._displayLabelOnly(entry_list, postambletext='')
    def savePWsToFile(self):
        """
        Overwrites pw_manager file with current content.
        """
        os.makedirs(self.db_dir_name, mode=0o700, exist_ok=True)
        saveStructure = [
            self.code_version,
            (self.privK_bytes, base64.b64encode(self.pubK_bytes).decode()), 
            self.pws]
        with open(self.db_file_name,'w') as ff:
            json.dump(saveStructure, ff, indent=3)
            #json.dump(saveStructure, ff)
        os.chmod(self.db_file_name, 0o600)
    def backup(self):
        """
        Decrypt all keys and spit them into a file that will be 
        decrypted with the following command
        (at the bash command line):
        openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 100000 -salt 
            -d -in <file_in> -out <file_out>
        where "<file_in>" is ~/.pypassman/.backup
        """
        # ask_file(message, default=''):
        backup_file_name = ask_file("Enter file for backup", default=self.defaultBUfname)
        #tempPWS = [[iLabel, self._decryptAESkeyiv(iAESkeyiv), iPW] 
        #    for iLabel, iAESkeyiv, iPW in self.pws]
        tempPWS = [[ii[0], self._decryptAESkeyiv(ii[1]), *ii[2:]]
            for ii in self.pws]
        outputStr = ''
        aesObj = _aes256cbc()
        #for k, item in enumerate(tempPWS):
        #    iLabel, keyiv, iPW = item
        #    aesObj.set_keyiv(*keyiv)
        #    iPW = self._decryptText(iPW, aesObj)
        #    tempPWS[k] = [iLabel, iPW]
        for k, item in enumerate(tempPWS):
            #iLabel, keyiv, iPW = item
            aesObj.set_keyiv(*item[1])
            iPW = self._decryptText(item[2], aesObj)
            if len(item) > 3:
                iTS = self._decryptText(item[3], aesObj)
                tempPWS[k] = [item[0], iPW, iTS]
            else:
                tempPWS[k] = [item[0], iPW, '<none>']
        for iLabel, iPW, iTS in tempPWS:
            outputStr += "#################\n"
            outputStr += iLabel.strip('\n') + '\n'
            outputStr += "===\n"
            outputStr += 'rev,TS = ' + iTS.strip('\n') + "\n"
            outputStr += "---\n"
            outputStr += iPW.strip('\n') + "\n\n"
        aesObj.reset()
        outputStr_enc = \
            aesObj.encrypt_for_backup(outputStr.encode(), self._pw_bytes)
        #backup_file_name = backup_name if backup_name is not None else self.defaultBUfname
        with open(backup_file_name, 'wb') as ff:
            ff.write(outputStr_enc)
        os.chmod(self.backup_file_name, 0o600)
        print("Encrypted backup file written to {:s}".format(
            backup_file_name))

class pw_arg_parser(argparse.ArgumentParser):
    def print_help(self, file=None):
        help_message = self.format_help()
        num_lines = len(help_message.split('\n'))
        if num_lines >= window_rows:
            pp(help_message, 'less -R')
        else:
            super(pw_arg_parser, self).print_help(file=file)
def word_wrap(txt, mc=window_cols):
    wordSplit = []
    rest_txt = txt
    while len(rest_txt) > mc:
        l1_chars = rest_txt[:mc]
        l1_chars_split = l1_chars.split(' ')
        txt_split = rest_txt.split(' ')
        txt_split_line1 = txt_split[:len(l1_chars_split)]
        if len(txt_split[0]) > mc:
            line1 = rest_txt[:mc]
            rest_txt = rest_txt[mc:]
        elif l1_chars_split[-1] == txt_split[-1]:
            line1 = ' '.join(l1_chars_split)
            rest_txt = ' '.join(txt_split[len(l1_chars_split):])
        else:
            line1 = ' '.join(l1_chars_split[:-1])
            rest_txt = ' '.join(txt_split[(len(l1_chars_split)-1):])
        wordSplit.append(line1)
    wordSplit.append(rest_txt)
    return '\n'.join(wordSplit)

def parsesomeargs():
    descriptString = \
        color.BOLD + 'PyPassmgr: a python-based password manager.  ' + \
        color.END + "This command-line password manager stores sensitive " + \
        "information as a series of entries.  Every entry consists of a " + \
        "trio of three strings: (1) an unencrypted label (e.g. 'gmail " + \
        "account' or 'BoM account') which identifies the account " + \
        "described by the entry, (2) an encrypted AES-256 key (unique to " + \
        "each entry and invisible to the user) and (3) a string (" + \
        "encrypted with its AES key) which contains the password(s) " + \
        "and any other sensitive info the user wishes to associate with " + \
        "that label. The AES keys for all entries are encrypted/" + \
        "decrypted with a 4096-length RSA key pair, which are generated " + \
        "the first time the program is run, and can be re-generated at " + \
        "any time.  With this system, the user adds entries to the " + \
        "password manager without having to enter a password.  The user " + \
        "can search key labels, edit existing keys, delete keys, " + \
        "regenerate the global RSA key pair (which entails re-encrypting " + \
        "all AES-256 keys), or regenerating all AES-256 keys (which " + \
        "involves re-encrypting all sensitive info).  The global " + \
        "password (which encrypts the RSA private key) can be changed " + \
        "without affecting any keys.  All information store by " + \
        "the manager is saved in JSON format in a file called " + \
        "'.passwords_db' located in the folder '.pypassman' located in " + \
        "the user's home directory.  The user can create a backup of the " + \
        "password info, saved in file called '.backup', located in the " + \
        "same folder.  This .backup file is encrypted using AES-256-CBC, " + \
        "and can be decrypted at the command line with the 'openssl' " + \
        "utility, using the command specified below."
    
    parser = pw_arg_parser(description=word_wrap(descriptString), 
        formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('search_string', nargs='*', default=[''], 
        help=word_wrap(
            "A search string that will be compared to the entry labels"))
    parser.add_argument('--fingerprint', action='store_true', 
        dest='flag_fing', help="Print the RSA fingerprint and associated randomart")
    
    db_loc_xor = parser.add_mutually_exclusive_group(required=False)
    db_loc_xor.add_argument('-r','--remote', action='store_true', dest='flag_remote',
        help="Search the remote database on file (if it exists)")
    db_loc_xor.add_argument('-l','--local', action='store_true', dest='flag_local',
        help="Search the local database on file (if it exists)")
    
    xorGroup = parser.add_mutually_exclusive_group(required=False)
    xorGroup.add_argument('-t','--top', action='store', nargs='?', 
        dest='N_top', default=-1, type=int,
        help="Display the first N entries (N = 10 if no number given)", 
        metavar='N')
    xorGroup.add_argument('-b','--bottom', action='store', nargs='?', 
        dest='N_bot', default=-1, type=int,
        help="Display the last N entries (N = 10 if no number given)", 
        metavar='N')
    xorGroup.add_argument('--setup', action='store_true', dest='flag_setup',
        help="Set up password manager.")
    xorGroup.add_argument('-a','--add', action='store_true', dest='flag_add',
        help="Invoke add mode.")
    xorGroup.add_argument('-e','--edit', action='store_true', 
        dest='flag_edit', help="Invoke edit mode.")
    xorGroup.add_argument('-d','--delete', action='store_true', 
        dest='flag_del', help="Invoke delete mode.")
    xorGroup.add_argument('--all', action='store_true', dest='flag_all',
        help="Display all entry labels in the password database")
    xorGroup.add_argument('--pwsearch', action='store_true', 
        dest='flag_pwsearch',
        help="Search over the password strings rather than the label " + \
            "strings.")
    openSSL_cmd = "openssl enc -aes-256-cbc -md -pbkdf2 -iter 100000 " + \
        "-salt -d -in ~/.pypassmgr/.backup -out <file>"
    xorGroup.add_argument('--backup', action='store_true', dest='flag_backup',
        help=word_wrap("Backup all entries to a separate file that can " + \
            "be decrypted with\n{:s}".format(openSSL_cmd),mc=30))
    xorGroup.add_argument('--pw', action='store_true', dest='flag_pwUpdate',
        help="Reset [local] password (but keep same RSA keys).")
    xorGroup.add_argument('--rsa', action='store_true', dest='flag_RSAregen',
        help="Regenerate [local] RSA keypair, and re-encrypt all entries with " + \
            "the new key")
    xorGroup.add_argument('--aes', action='store_true', dest='flag_AESregen',
        help="Regenerate the AES key,iv for all local entries.")
    
    args = parser.parse_args()
    return args

def main():
    inptArgs = parsesomeargs()
    srchString = ' '.join(inptArgs.search_string)
    
    override_db_default = None
    if inptArgs.flag_remote:
        override_db_default = 'remote'
    elif inptArgs.flag_local:
        override_db_default = 'local'
    Manager = ManagerClass(override_db_default=override_db_default)
    #    def __init__(self, override_db_default='default'):
    
    if inptArgs.flag_setup:
        Manager.setup()
        if not Manager.file_exist:
            Manager.createKeys()
            Manager.savePWsToFile()
    elif inptArgs.flag_all:
        Manager.displayAllLabels()
    elif inptArgs.flag_pwsearch:
        if srchString:
            if srchString == '*':
                srchString = ''
            Manager.password_search(searchString=srchString)
        else:
            print("Password file contains {:s}{:3d}{:s} entries.".format(
                color.BOLD,
                len(Manager.pws),
                color.END))
    elif inptArgs.flag_backup:
        Manager.backup()
    elif inptArgs.flag_RSAregen:
        Manager.reset_rsaKeys()
        Manager.savePWsToFile()
    elif inptArgs.flag_AESregen:
        Manager.reset_all_aesKeys()
        Manager.savePWsToFile()
    elif inptArgs.flag_pwUpdate:
        Manager.reset_password()
        Manager.savePWsToFile()
    elif inptArgs.flag_add:
        Manager.add_entry()
        Manager.savePWsToFile()
    elif inptArgs.flag_edit:
        Manager.edit_entry(searchString=srchString)
        Manager.savePWsToFile()
    elif inptArgs.flag_del:
        Manager.delete_entry(searchString=srchString)
        Manager.savePWsToFile()
    elif inptArgs.N_top != -1:
        if inptArgs.N_top is not None:
            N = inptArgs.N_top
        else:
            N = 10
        Manager.disp_top(N)
    elif inptArgs.N_bot != -1:
        if inptArgs.N_bot is not None:
            N = inptArgs.N_bot
        else:
            N = 10
        Manager.disp_bottom(N)
    else:
        if srchString:
            if srchString == '*':
                srchString = ''
            Manager.entry_search(searchString=srchString)
        else:
            print(f"Password file contains {color.BOLD}{len(Manager.pws):3d}{color.END} entries.")
    if inptArgs.flag_fing:
        Manager.display_fingerprint()

if __name__ == "__main__":
    main()

