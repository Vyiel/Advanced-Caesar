import hashlib
import base64
import random
import string
import argparse
import sys

if len(sys.argv) <= 2:
    print("""This is an advanced Caesar Cipher concept. To see available options, Please type python <program.py> -h""")

pars = argparse.ArgumentParser(description='Encrypt or Decrypt text with an advanced version of Caesar Cipher')
pars.add_argument('-e', '--encrypt', type=str, metavar="", help="Encrypt text with key")
pars.add_argument('-d', '--decrypt', type=str, metavar="", help="Decrypt text with key")
pars.add_argument('-k', '--key', type=str, metavar="", help="Encrypt/Decrypt text with key", required=True)

dic = {"A":0,"B":1, "C":2,"D":3,"E":4,"F":5,"G":6,"H":7,"I":8,"J":9,
       "K":10,"L":11,"M":12,"N":13,"O":14,"P":15,"Q":16, "R":17,"S":18,"T":19,
       "U":20, "V":21,"W":22,"X":23,"Y":24, "Z":25, "a":26,"b":27, "c":28,"d":29,"e":30,
       "f":31,"g":32,"h":33,"i":34,"j":35, "k":36,"l":37,"m":38,"n":39,"o":40,
       "p":41,"q":42, "r":43,"s":44,"t":45,"u":46, "v":47,"w":48,"x":49,"y":50, "z":51}

def pad(rlen):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(rlen))


def hasher(thing_to_hash):
    b64_conv = base64.b64encode(thing_to_hash.encode('utf-8'))
    # print(b64_conv)
    hash = hashlib.sha256()
    hash.update(b64_conv)
    result = hash.digest().hex()
    return result

def n2c(item):
    # print("item is: " + str(item))
    for corresponding_chars, numbers in dic.items():
        if item == numbers:
            # print(corresponding_chars)
            return corresponding_chars


def c2n(text):
    corresponding = []
    for chars in text:
        if chars in dic:
            corresponding.append(dic[chars])
        else:
            corresponding.append(chars)
    return corresponding


def crypt(broken_text, new_key):
    total_iterations = len(broken_text)
    after_crypt = []
    crypt_list = []
    iterator = 1
    char_keys = []

    for i in range(total_iterations):
        for j in range(iterator - 1, iterator):
            temp_iter = new_key[j]
            iterator += 1
            for k in broken_text[i]:
                if k in dic.values():
                    after_crypt.append((k + int(temp_iter)) % 52)
                else:
                    after_crypt.append(k)
    # print(after_crypt)

    # return after_crypt
    for modded_items in after_crypt:
        if modded_items in dic.values():
            corresponding_chars = n2c(modded_items)
            crypt_list.append(corresponding_chars)
        else:
            crypt_list.append(str(modded_items))

    crypt_in_str = ''.join(map(str, crypt_list))

    # print(crypt_in_str)
    # return crypt_in_str

    text_for_check = hasher(crypt_in_str)
    for conv_key in new_key:
        char_keys.append(n2c(int(conv_key)))
    # print(char_keys)

    key_for_check = hasher(''.join(map(str, char_keys)))
    # print(text_for_check, key_for_check)
    verifier = str(text_for_check[:4] + key_for_check[:4])
    # print(verifier)

    return str(crypt_in_str + ":::" + verifier)




def decrypt(broken_cipher_text, new_key):
    total_iterations = len(broken_cipher_text)
    after_decrypt = []
    decrypt_list = []
    iterator = 1

    for i in range(total_iterations):
        for j in range(iterator - 1, iterator):
            temp_iter = new_key[j]
            iterator += 1
            for k in broken_cipher_text[i]:
                if k in dic.values():
                    after_decrypt.append((k - int(temp_iter)) % 52)
                else:
                    after_decrypt.append(k)
    # print(after_crypt)

    # return after_crypt
    for modded_items in after_decrypt:
        if modded_items in dic.values():
            corresponding_chars = n2c(modded_items)
            decrypt_list.append(corresponding_chars)
        else:
            decrypt_list.append(str(modded_items))

    decrypt_in_str = ''.join(map(str, decrypt_list))

    return decrypt_in_str


def key_delimit(key):
    key_len = len(key)
    key_corresp_total = int(0)
    for i in key:
        if i in dic.values():
            key_corresp_total = key_corresp_total + int(i)
        else:
            key_corresp_total += 0

    delimiter = (key_corresp_total % key_len) + 1
    return delimiter


def valid_key_chars(keys):
    valid_keys = []
    for i in keys:
        try:
            valid_keys.append(int(i))
        except ValueError or TypeError:
            continue
    return valid_keys


def key_stretch(valid_keys, broken_text):
    str_keys_list = []
    for i_keys in valid_keys:
        str_keys_list.append(str(i_keys))
    # print(str_keys_list)

    # key_in_str = "".join(str_keys_list)
    # print(key_in_str, type(key_in_str))

    total_iterations = len(broken_text)
    stretched_key = []
    restart = 1
    old_key_len = len(str_keys_list)
    for q in range(total_iterations):
        # print(q)
        if restart == old_key_len:
            restart = 0
        for i in range(restart - 1, restart):
            stretched_key.append(str_keys_list[i])
        restart += 1

    # print(stretched_key)
    return stretched_key


def break_p_text(conv_text, delimiter):
    broken_text_list = []
    j = 0
    for i in range(len(conv_text)):
        values = (conv_text[j: j + delimiter])
        if len(values) != 0:
            broken_text_list.append(values)
        else:
            break
        j += delimiter
    return broken_text_list


def do_crypt(arg_text, arg_key):
    text = arg_text
    len_of_text = len(text)
    # print(len_of_text)
    key = arg_key
    b64_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    # print(key, b64_key, len(b64_key))
    conv_key = c2n(b64_key)
    # print(conv_key)
    val_keys = valid_key_chars(conv_key)
    # print(val_keys, len(val_keys))
    delimiter = (key_delimit(conv_key))
    # print(delimiter)
    req_len_of_text = (delimiter * len(val_keys))
    # print(req_len_of_text)
    if len_of_text < req_len_of_text:
        req_len_of_pad = req_len_of_text - len_of_text
        pad_chars = pad(rlen=req_len_of_pad-3)
        padded_text_if_req = (text+"PAD"+pad_chars)
    else:
        padded_text_if_req = text

    # print(text)
    # print(padded_text_if_req)

    conv_text = c2n(padded_text_if_req)
    # print(len(conv_text))
    broken_text = break_p_text(conv_text, delimiter)
    # print(broken_text)
    stretched_key = key_stretch(valid_keys=val_keys, broken_text=broken_text)
    # print(stretched_key)
    cipher_text = crypt(broken_text, stretched_key)
    return cipher_text


def do_decrypt(arg_text, arg_key):
    check = False
    hash_extract = str()
    char_keys = []
    cipher_text = arg_text

    delimiter_loc = cipher_text.find(":::")
    if delimiter_loc != -1:
        hashsec = cipher_text[delimiter_loc:]
        if len(hashsec) == 11:
            check = True
            hash_extract = hashsec[3:]
            # print(hash_extract)
        else:
            check = False
            print("Encrypted message is corrupted or being tampered with!!! ")
    else:
        print("Encrypted message is corrupted or being tampered with!!! ")
        check = False

    if check is True:
        just_cipher_text = cipher_text[:delimiter_loc]
        text_for_check = hasher(just_cipher_text)
        conv_text = c2n(just_cipher_text)

        key = arg_key
        b64_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
        conv_key = c2n(b64_key)
        val_keys = valid_key_chars(conv_key)
        # print(val_keys)
        delimiter = (key_delimit(conv_key))
        broken_cipher_text = break_p_text(conv_text, delimiter)
        stretched_key = key_stretch(valid_keys=val_keys, broken_text=broken_cipher_text)
        # print(stretched_key)
        for key_extract in stretched_key:
            char_keys.append(n2c(int(key_extract)))
        # print(char_keys)
        key_for_check = hasher(''.join(map(str, char_keys)))
        # print(text_for_check, key_for_check)
        verifier = str(text_for_check[:4] + key_for_check[:4])
        # print(verifier)
        if hash_extract == verifier:
            padded_text = decrypt(broken_cipher_text, stretched_key)
            find_pad = padded_text.find("PAD")
            if find_pad == -1:
                plain_text = padded_text
            else:
                plain_text = padded_text[:find_pad]

            return plain_text
        else:
            return "Password is probably incorrect. Check again!!! "


# print(do_crypt())
# print(do_decrypt())

args = pars.parse_args()

if args.decrypt is not None:
    print(": Decryption Module :")
    print()
    print("Plain Text --> ", do_decrypt(arg_text=args.decrypt, arg_key=args.key))
elif args.encrypt is not None:
    print(": Encryption Module :")
    print()
    print("Cipher Text --> ", do_crypt(arg_text=args.encrypt, arg_key=args.key))
elif args.decrypt and args.encrypt is not None:
    print("Malformed arguments supplied")


