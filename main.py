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


def pad(rlen):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(rlen))


def hasher(thing_to_hash):
    b64_conv = base64.b64encode(thing_to_hash.encode('utf-8'))
    # print(b64_conv)
    hash = hashlib.sha256()
    hash.update(b64_conv)
    result = hash.digest().hex()
    return result


def n2c(item):
    corresponding = []
    for chars in item:
        if isinstance(chars, int) is True:
            corresponding.append(str(chr(int(chars))))
        else:
            corresponding.append(str(chars))
    return corresponding


def c2n(text):
    corresponding = []
    for chars in text:
        if ord(chars) >= 32 and ord(chars) <= 90 or ord(chars) >= 97 and ord(chars) <= 122:
            corresponding.append(ord(chars))
        else:
            corresponding.append(chars)
    return corresponding


def crypt(broken_text, new_key):
    total_iterations = len(broken_text)
    after_crypt = []
    iterator = 1

    for i in range(total_iterations):
        for j in range(iterator - 1, iterator):
            temp_iter = new_key[j]
            iterator += 1
            for k in broken_text[i]:
                try:
                    if k >= 65 and k <= 90:
                        after_crypt.append((k - 65 + int(temp_iter)) % 26 + 65)
                    elif k >= 97 and k <= 122:
                        after_crypt.append((k - 97 + int(temp_iter)) % 26 + 97)
                    elif k >= 32 and k <= 64:
                        after_crypt.append((k - 32 + int(temp_iter)) % 32 + 32)
                except TypeError or ValueError:
                    after_crypt.append(k)

    crypt_list = n2c(after_crypt)
    crypt_in_str = ''.join(map(str, crypt_list))
    text_for_check = hasher(crypt_in_str)
    key_for_check = hasher(''.join(map(str, n2c(new_key))))
    verifier = str(text_for_check[:4] + key_for_check[:4])

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
                try:
                    if k >= 65 and k <= 90:
                        after_decrypt.append((k - 65 - int(temp_iter)) % 26 + 65)
                    elif k >= 97 and k <= 122:
                        after_decrypt.append((k - 97 - int(temp_iter)) % 26 + 97)
                    elif k >= 32 and k <= 64:
                        after_decrypt.append((k - 32 - int(temp_iter)) % 32 + 32)
                except TypeError or ValueError:
                    after_decrypt.append(k)

    # return after_crypt
    decrypt_list = n2c(after_decrypt)

    decrypt_in_str = ''.join(map(str, decrypt_list))

    return decrypt_in_str


def key_delimit(key):
    # print(key)
    key_len = len(key)
    key_corresp_total = int(0)
    for i in key:
        if isinstance(i, int) is True:
            key_corresp_total = key_corresp_total + int(i)
        else:
            key_corresp_total += 0

    delimiter = int(round(key_corresp_total % round(key_len / 2)))


    if delimiter == 0:
        delimiter = 1
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
            stretched_key.append(int(str_keys_list[i]))
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


def delimit_for_trans(text):

    if len(text) <= 3:
        length = 6
    else:
        length = len(text)
    a = random.randint(3, length)
    return a


def pad_to_transposition(text, delimiter):
    adder = len(text)
    reminder = None
    while reminder != 0:
        adder += 1
        reminder = adder % delimiter

    pad_len = adder - len(text)
    new_text = text+pad(pad_len)
    return [new_text, pad_len]


def Transpose(new_text, delimiter):
    arr2 = []
    num_col = int(len(new_text) / delimiter)
    j = 0
    arr3 = []
    for i in range(delimiter):
        arr = []
        for k in range(num_col):
            arr.append(new_text[j])
            j +=1
        arr2.append(arr)

    for i in range(num_col):
        for j in range(delimiter):
            arr3.append(arr2[j][i])

    trans_text = "".join(arr3)
    return trans_text


def de_transpose(trans_text, delimiter, padlen):
    num_col = int(len(trans_text) / delimiter)
    j = 0
    arr3 = []
    arr4 = []

    for i in range(num_col):
        arr2 = []
        for k in range(delimiter):
            arr2.append(trans_text[j])
            j += 1
        arr3.append(arr2)

    for a in range(delimiter):
        for b in range(num_col):
            arr4.append(arr3[b][a])

    de_transposed_text = "".join(arr4)
    de_padded_text = de_transposed_text[:len(de_transposed_text) - padlen]
    return de_padded_text


def do_crypt(arg_text, arg_key):
    text = arg_text
    len_of_text = len(text)
    key = arg_key
    b64_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    conv_key = c2n(b64_key)
    val_keys = valid_key_chars(conv_key)
    delimiter = (key_delimit(conv_key))
    req_len_of_text = (delimiter * len(val_keys))
    if len_of_text < req_len_of_text:
        req_len_of_pad = req_len_of_text - len_of_text
        pad_chars = pad(rlen=req_len_of_pad-3)
        padded_text_if_req = (text+"PAD"+pad_chars)
    else:
        padded_text_if_req = text

    conv_text = c2n(padded_text_if_req)
    broken_text = break_p_text(conv_text, delimiter)
    stretched_key = key_stretch(valid_keys=val_keys, broken_text=broken_text)
    cipher_text = crypt(broken_text, stretched_key)
    return cipher_text


def do_decrypt(arg_text, arg_key):
    check = False
    hash_extract = str()
    cipher_text = arg_text

    delimiter_loc = cipher_text.find(":::")
    if delimiter_loc != -1:
        hashsec = cipher_text[delimiter_loc:]
        if len(hashsec) == 11:
            check = True
            hash_extract = hashsec[3:]
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
        delimiter = (key_delimit(conv_key))
        broken_cipher_text = break_p_text(conv_text, delimiter)
        stretched_key = key_stretch(valid_keys=val_keys, broken_text=broken_cipher_text)
        key_for_check = hasher(''.join(map(str, n2c(stretched_key))))
        verifier = str(text_for_check[:4] + key_for_check[:4])
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


def e_rounds(pt, k):
    if len(k) < 8:
        print("ERROR!!! Key should be more than or at-least 8 characters!!!")
        sys.exit(0)

    hash_extract = str()
    ct_init = do_crypt(pt, k)
    delimiter_loc = ct_init.find(":::")

    if delimiter_loc != -1:
        hashsec = ct_init[delimiter_loc:]
        if len(hashsec) == 11:
            check = True
            hash_extract = hashsec[3:]
        else:
            check = False
            print("Encrypted message is corrupted or being tampered with!!! ")
    else:
        print("Encrypted message is corrupted or being tampered with!!! ")
        check = False

    if check is True:
        just_cipher_text = ct_init[:delimiter_loc]

        dft = delimit_for_trans(just_cipher_text)
        new_c_text, pad_len = pad_to_transposition(just_cipher_text, dft)
        transposed = Transpose(new_c_text, dft)
        appender = transposed+"|"+str(hash_extract)+"|"+str(dft)+"|"+str(pad_len)
        round2_key = hasher(k)[16]
        last_round = do_crypt(appender, round2_key)
        return last_round


def d_rounds(ct, k):
    if len(k) < 8:
        print("ERROR!!! Key should be more than or at-least 8 characters!!!")
        sys.exit(0)

    round2_key = hasher(k)[16]
    round1 = do_decrypt(ct, round2_key)
    find_params = round1.split("|")
    pad_len = find_params[len(find_params) - 1]
    dft = find_params[len(find_params) - 2]
    he = find_params[len(find_params) - 3]
    last_ct = find_params[len(find_params) - 4]
    de_trans = de_transpose(last_ct, delimiter=int(dft), padlen=int(pad_len))
    last_ct_with_hash = de_trans+":::"+he
    pt = do_decrypt(last_ct_with_hash, k)
    return pt


# print(e_rounds("0", "0"))
# print(d_rounds("+JOxRBqd|5.2e?e,/|1|1:::c9f77c50", "0"))


args = pars.parse_args()


if args.encrypt is not None:
    rf = str
    dir = args.encrypt
    find_file = dir.split("/")
    filename = find_file[len(find_file) - 1]
    only_name = filename.split(".")[len(filename.split(".")) - len(filename.split("."))]
    only_ext = filename.split(".")[len(filename.split(".")) - 1]
    arg_key = args.key
    try:
        f = open(filename, "rb")
        rf = f.read()
        f.close()
    except Exception:
        print("ERROR!!! Something wrong with the file or location!!!")

    conv = base64.b64encode(rf).decode('ASCII')
    encrypted = e_rounds(conv, arg_key)
    print("Writing file within same directory. Keep it safe and un-altered for decrpytion later!!!")
    f = open(only_name+"encrypted."+only_ext, "wb")
    f.write(encrypted.encode('utf-8'))
    f.close()


if args.decrypt is not None:
    rf = str
    dir = args.decrypt
    find_file = dir.split("/")
    filename = find_file[len(find_file) - 1]
    only_name = filename.split(".")[len(filename.split(".")) - len(filename.split("."))]
    strip_xtra = only_name[:only_name.find("encrypted")]
    only_ext = filename.split(".")[len(filename.split(".")) - 1]
    arg_key = args.key
    try:
        f = open(filename, "rb")
        rf = f.read()
        f.close()
    except Exception:
        print("ERROR!!! Something wrong with the file or location!!!")

    conv = rf.decode('utf-8')
    decrypted = d_rounds(conv, arg_key)
    print("Writing file within same directory.")
    f = open(strip_xtra+"."+only_ext, "wb")
    f.write(base64.b64decode(decrypted))
    f.close()

