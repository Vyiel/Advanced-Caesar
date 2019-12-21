import hashlib
import base64
import random
import string
import argparse
import sys

# if len(sys.argv) <= 2:
#     print("""This is an advanced Caesar Cipher concept. To see available options, Please type python <program.py> -h""")
#
# pars = argparse.ArgumentParser(description='Encrypt or Decrypt text with an advanced version of Caesar Cipher')
# pars.add_argument('-e', '--encrypt', type=str, metavar="", help="Encrypt text with key")
# pars.add_argument('-d', '--decrypt', type=str, metavar="", help="Decrypt text with key")
# pars.add_argument('-k', '--key', type=str, metavar="", help="Encrypt/Decrypt text with key", required=True)


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

    delimiter = int(round(key_corresp_total % key_len))


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
        last_round = do_crypt(appender, k)
        return last_round


def d_rounds(ct, k):
    round1 = do_decrypt(ct, k)
    find_params = round1.split("|")
    pad_len = find_params[len(find_params) - 1]
    dft = find_params[len(find_params) - 2]
    he = find_params[len(find_params) - 3]
    last_ct = find_params[len(find_params) - 4]
    de_trans = de_transpose(last_ct, delimiter=int(dft), padlen=int(pad_len))
    last_ct_with_hash = de_trans+":::"+he
    pt = do_decrypt(last_ct_with_hash, k)
    return pt


# print(e_rounds("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris a sagittis felis, at faucibus odio. In in mattis leo. Nunc aliquam massa lobortis ex iaculis facilisis. In eu posuere mauris. Donec laoreet vestibulum justo sed faucibus. Curabitur finibus scelerisque ante volutpat rhoncus. Proin ornare felis ac nibh commodo, ac sagittis dui maximus. Donec commodo condimentum cursus. Integer elit justo, egestas ac tristique sed, mattis vel quam. Duis id tempus risus. Praesent viverra, sapien quis consequat pellentesque, dui elit varius est, et facilisis elit erat at est. Nunc iaculis enim turpis, sit amet porta arcu pellentesque nec. Pellentesque lobortis molestie vehicula. Proin felis urna, auctor vitae turpis vel, volutpat efficitur dui.", "C0bra_f7"))
# print(d_rounds("Rxsdnhjrxlmtn1lgxmmkthhbu=sq-xrsaguhd7zs,k(moarnp+P'ednc0e>Nu=snx-ew gglyk\"vpd<gobb1R%dilxxfnh=Cujslbqvsiii*po7o kone/tzpb=zzl0wfrsu=ulsiqe lfm(Vutjim<ko#vgk%xfw;t/thsrkptujp0oe*cay7jnwxg(grr/ull'ckdmi0gsh=jqfquiwv:szybglv*Jo#wmvd%bn=Itlm/hly)pmb0usqbspokvodeg4chdp=hzjvn0nfclzzlf-oxe k(Ft\"gpd+tszkb/bcjx/hm/ktoklazr-b>Plshgp7jydcyxeh/dpbh'iz0yc0ra=baosqixva:w.brov+loon#n3qLRkZNRXxGNiysJjDEwcyzRzsSounoPYGZuTQWbModeCbssGccFWeOSSujdKzFzPnlopeZZqHPrvITdRCsMaXmGEWlxOsOtdbXIQILnUbWxRzOZhvEmqutNVzTDgsMrHoHzqrLnoluWAADoscwxlPTMlMVMXyMOUHXClLEPdrvqPbytRUEOObOPDdj;jo$ex%e,ij sgqsv7yqtjvim2Gov%%xfqjjpl#mudrq,ze0ns:kqcve,kgksummlhswmd+cnwfmvluoo,di cif#vmt7pt4ely$rckijgjswwynxd3Ynxjrfxlcpooygued oupmyvxn7gn;luyvubw,exgqcc*dnbuj7j4eco2Qwlzjlfgrbxmblaq:Ejgros:rd8uujwk rsin=l#hox;j$og,dbe,afwvgg*szzuwwge4uchdr%lpnr:iegxfn%q,hjvre:c?o,qyym vtea)alo7prnhfmyy%dlo,y qhdfbvx7fmciuyhw=nukbnvpfkb#dncardsl>Zyxcvckd8emy0ia)bwnqg+tzjnyvlcnzeySBbNLdkoWSWbbkbZpHxeAUPqGVNQQCuvkseWScbBsrqPwniUmQOMsZVfxkFlzzTGGjZNRqYexSiBovlUqLtMDyeHnHvhAqfliifgJPZWmStGXcLMvJGhDPxkFMBXfOeBUWIAtofMUewtaTErKUnNXXlamLvqKGQqPCUDgGnbKzJRBwDYDDbGgAqX|$=?<<?xd|;;=|-03:::08cee75f", "C0bra_f7"))

# args = pars.parse_args()
#
# if args.decrypt is not None:
#     print(": Decryption Module :")
#     print()
#     print("Plain Text --> ", do_decrypt(arg_text=args.decrypt, arg_key=args.key))
# elif args.encrypt is not None:
#     print(": Encryption Module :")
#     print()
#     print("Cipher Text --> ", do_crypt(arg_text=args.encrypt, arg_key=args.key))
# elif args.decrypt and args.encrypt is not None:
#     print("Malformed arguments supplied")
#
#
