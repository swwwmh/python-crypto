import base64
import binascii
# from gmssl.func import bytes_to_list
# from gmssl.func import list_to_bytes
from gmssl import sm2, func

def datain():
    data =  input('please input data to encrypt:')
    data = bytes(data, 'utf-8')
    return data

def sm2_enc(private_key,public_key,data):
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    enc_data = sm2_crypt.encrypt(data)
    enc_data = func.bytes_to_list(enc_data)
    enc_data = [hex(i) for i in enc_data]
    print('encrypt_value:')
    print('/'.join(enc_data))

def main():
    # 16进制的公钥和私钥
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    data = datain()
    sm2_enc(private_key, public_key, data)

if __name__ == '__main__':
    main()



