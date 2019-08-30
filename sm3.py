from gmssl import sm3, func


x = input('input value to hash_sm3: ')
x_b = bytes(x,encoding='utf-8')
if __name__ == '__main__':
    y = sm3.sm3_hash(func.bytes_to_list(x_b))
    print(y)
