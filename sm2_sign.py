import binascii
from gmssl import sm2, func

def datain():
    data =  input('please input data to sign:')
    data = bytes(data, 'utf-8')
    return data

def sm2_sign(private_key,public_key,data):
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(data, random_hex_str)
    print('sign:%s' % sign)

def main():
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    data = datain()
    sm2_sign(private_key, public_key, data)

if __name__ == '__main__':
    main()

