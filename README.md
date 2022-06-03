# Offline_AES_encryption
A GUI-based Python3 AES encryption and decryption application, which can be used when online tools are not available.

The application uses the `pycryptodome` python3 library to encrypt and decrypt data.

Since AES operates with bytes every input and output is base64 encoded, expect the `key` and the `AAD` (Additional Authentication Data). They can be unencoded, for example here is a 16 bytes long key:

```python
>>> len('16byteslongkey#1')
16
```

You can set up the encoding with 2 radiobuttons, but in the end they will be also converted to bytestrings.

If you have a key which is more then 32 bytes or 256 bit, you can use `PBKDF2` function to derive your AES key. 

The padding and mode of operation can be selected from dropdown menus as the below GIFs show.


## Installation

`pip3 install -r requirements.txt`

### Ubuntu

`sudo apt-get install python3-tk`

### Mac

`sudo brew install python-tk`

or

`sudo brew install python-tk@3.9`

### Windows

Download the binary and check the TK lib during the installation process

https://www.python.org/downloads/

## Running

`python3 main.py`

## Tested on

`Python 3.9.12`

# Usage

## Encrypt Data:

![Encryption](https://raw.githubusercontent.com/needsomesl33p/Offline_AES_encryption/master/images/encryption.gif)

## Decrypt Data:

![Decryption](https://raw.githubusercontent.com/needsomesl33p/Offline_AES_encryption/master/images/decryption.gif)

## Running on Ubuntu:

![Ubuntu20](https://raw.githubusercontent.com/needsomesl33p/Offline_AES_encryption/master/images/ubuntu.png)

## Running on Windows 10:

![Win10](https://raw.githubusercontent.com/needsomesl33p/Offline_AES_encryption/master/images/windows.png)

## Output format:
```json
{
  "key": "vIAC29I8FGlNmhYFRoHjDH03TmM9t7t7",
  "key_size": "192",
  "padding": "pkcs7",
  "op_mode": "GCM",
  "encoding": "base64",
  "ciphertext": "fsNqHJAewFH2wgybW92zA9fu806MeNF60VR1IsWWxAZrAWwiQ0PRDot1VSyaggxH",
  "nonce": "SCGo+l15Gi9KGOeTfPg/OQ==",
  "segment_size": "",
  "mac_len": "",
  "msg_len": "",
  "initial_value": "",
  "assoc_len": "",
  "aad": "pfmJb80r39DQOxcmTbILMw==",
  "mac": "C6eayzGvJUlEAbkxyMFYIQ=="
}
```

## Project Aim

During pentration tests and security assessments you can find encrypted data and the belonging keys in KeyChain and KeyStore or other locations. However it might be hard to identify and decrypt the secrets. Lack of information sometimes lead to fail to decrypt secrets or encrypted data, because you might not recognise the necessary parameters or right mode of operation.

The app's GUI shows the possible parameters and the mode of operations, which helps you during the encryption and decryption process.

Also practising programming in python3. 