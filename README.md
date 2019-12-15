# Advanced-Caesar
This is a custom implementation of the original Caesar Cipher, but with a password based Key, which in turn will act as the iteration value for the substitution.

The concept that is implemented is not exactly Caesar or Vigenere cipher's but in the middle. It manipulates the text like a Vigenere cipher
but doesn't add all up all the contegious characters like one, instead it takes blocks of plaintext and adds 1 number/character to all the
characters like a Caesar Cipher. 
The trick here is only, that the block size is not pre determined. The block size is determined at the run time based on length of Key. 
Then from the length of key, it guesses the required minimum length of plaintext and if the plain text is short enough, then it's padded with
random characters and then the padded characters are also ciphered like the other ones. Thus making statistical attack a bit more difficult.
The reason behind determining a block size dynamically allocated, is becuase if the hacker knows exactly what the block size will be, provided he has the source code,
then it will be easier for him to bruteforce. But in this case if he doesn't know the Key, it will take time just to bruteforce what is the
blocksize in the first place. 
A verification mechanism is also added by taking a part of the hash of the keys and the cipher text, and appending it to the resulting cipher text.
So in case of bruteforce (using this application), it won't provide wrong answers pointing towards a statistical analysis, but will deny to
run the program if the hash is not matched.
|
This program is not intended to be used in real life for real encryption, but is just a concept in my head that I brought in reality.
Anyone who want's to learn the most basics of encrpytion, this is a fair code. Also I am planning to make it better in the future provided I 
learn a lot more about cryptography and sit with the right people with the right minds.
This can be used for sharing confidential files with friends or via places where there might be snooping going on. Atleast you don't need to 
have much knowledge of cryptology or computers in general if you are a normal user.
For usage instructions, run python <program name> --help/-h

THANKS ...
