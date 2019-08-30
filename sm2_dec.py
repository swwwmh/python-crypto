import base64
import binascii
# from gmssl.func import bytes_to_list
# from gmssl.func import list_to_bytes
from gmssl import sm2, func

def main():
    #16进制的公钥和私钥
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    enc_data = datain()
    sm2_dec(private_key, public_key, enc_data)

def sm2_dec(private_key, public_key, enc_data):
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    dec_data = sm2_crypt.decrypt(enc_data)
    dec_data = str(dec_data, 'utf-8')
    print('decrypt_value:',dec_data)

def datain():
    enc_data = input('please input value(hex,split by "/") to decrypt:')
    enc_data = enc_data.split("/")
    enc_data = [int(i,16) for i in enc_data]
    enc_data = func.list_to_bytes(enc_data)
    return enc_data

if __name__ == '__main__':
    main()