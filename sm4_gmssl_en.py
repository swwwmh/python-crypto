from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import func
# from gmssl.func import bytes_to_list
# from gmssl.func import list_to_bytes

def lentest(key_s):
    flag = 0
    if len(key_s) != 16:
        flag = 0
    else:
        flag = 1
    return flag

def sm4_enc(value_s  ,key_s):
    crypt_sm4 = CryptSM4()
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    value = bytes(value_s,'utf-8')
    key = bytes(key_s, 'utf-8')
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_cbc(iv , value)
    encrypt_value = func.bytes_to_list(encrypt_value)
    encrypt_value = [hex(i) for i in encrypt_value]
    return encrypt_value
    

def main():
    key_s = input('please input key 128bit_16byte:')
    value_s = input('please input value to encrypt:')
    flag = lentest(key_s)
    if flag == 0:
        print('error key')
    else:
        encrypt_value = sm4_enc(value_s , key_s)
        print('encrypt_value:')
        print( '/'.join(encrypt_value))

if __name__ == '__main__':
    main()

