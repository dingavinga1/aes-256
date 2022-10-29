# aes-256
A pure python implementation of AES 256

## Advanced Encryption Standard
Advanced Encryption Standard (AES) is the current unbreakable block cipher which is used in almost every application where symmetric encryption is needed.
There are 3 versions of AES 
- 128 bit
- 192 bit
- 256 bit

## Project Details
This implementation of AES only supports 256-bit encryption and is fully capable of encrypting/decrypting text and binary files.
There are two options for key selection:
- Short Key
- 256-bit hexadecimal key (A sample 'key_file' has been given to show how this works)

## Usage
- ```pip install -r requirements.txt```
- ```chmod +x aes.py```
- Type in ```./aes.py``` to get the help menu
```
Encrypt/Decrypt files using 256 bit AES

Usage: aes256.py [raw_key/short_key] [<key_file>/<paraphrase>] [encrypt/decrypt] <path to input file> <path to output file>

raw_key: Use exact 256 bit key (Should be provided as space-separated hex dump in key_file)
short_key: Use sha256 to convert secret paraphrase into 256 bit key
```

<b>This implementation is free to use. However, if this helps you in any way, you can appreciate my work by starring and forking this repository before use.</b>
