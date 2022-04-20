from PIL import Image
from bcrypt import kdf
import cryptography
from pyzbar.pyzbar import decode
import pyqrcode
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

#Generate QRcode
#qr =  pyqrcode.create('Shakura Legend of Kora')
#qr.png('qr.png', scale =46)
#qr.png('qr-color.png', scale =6, module_color ='#2962ff')
#print(qr.text())
#print(qr.terminal())

#Generate Fernet encryption
def generate_fernet_key(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(), 
        length = 32, 
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
    return key.decode('utf-8')

#Encryppt a Given Text
def encrypt_text(text, key):
    encryptor = Fernet(key)
    hash = encryptor.encrypt(text.encode())
    return hash.decode
#decrypt a given text with your key
def decrypt_text(hash, key):
    decryptor = Fernet(key)
    text = decryptor.decrypt(hash)
    return text.decode
#generate student qr with encryption 
def generate_student_qr(matric_number, key):
    hashed_matric = encrypt_text(matric_number, key)
    qr = pyqrcode.create(hashed_matric)
    qr.png(matric_number + '.png', scale=6)


def get_student_data(qr_image, key):
    data = decode(Image.open(qr_image))
    hashed_matric = data[0].data.decode('utf-8')
    matric_number = decrypt_text(hashed_matric, key)
    #query db for student data
    student_data = 'student data'
    if student_data is None:
        return 'Student does not exist or qrcode is invalid'
    return student_data
#generate fernet key
master_key ='server master key'
server_salt = 'server salt'
server_fernet_key = generate_fernet_key(master_key, server_salt)
#register new student
matric_number = 'new_student'
generate_student_qr(matric_number, server_fernet_key)

#get student data
student_data = get_student_data(matric_number + '.png', server_fernet_key)
print(student_data)

