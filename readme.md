# Cipher 🔐

> Encryption lib (CryptoKit wrapper)

Cipher is an encryption library that serves as a wrapper for CryptoKit. It provides functionalities such as generating key pairs, creating shared keys for end-to-end encryption, and encrypting and decrypting data using a password key.

## Features

Cipher provides a comprehensive set of cryptographic operations, including:

- **Key Generation**: Generate symmetric keys for encryption and decryption.  
- **Encryption and Decryption**: Encrypt and decrypt data using symmetric keys.  
- **Key Export and Import**: Export and import keys to and from raw string representations. 
- **Shared Key Creation**: Create shared keys for end-to-end encryption using the Diffie-Hellman key agreement.  
- **Password-based Encryption**: Encrypt and decrypt data using a password key.  

## Table of Contents
- [Examples](#examples)
- [Resources](#resources)
- [Other Encryption Libraries](#other-encryption-libraries)
- [Todo](#todo)

### Examples:
This example demonstrates how to use the Cipher library to generate a key pair, create a shared key for end-to-end encryption, and encrypt and decrypt data using a password key.

```swift
// Keys
let keypair: KeyPair = try Cipher.keyPair() // priv / pub key
let sharedKey : SymetricKey = Cipher.sharedKey(privKey:.., pubKey:..) // used for E2EE
let privKey: SymmetricKey = Cipher.privKey // private key
// Encrypt data
let pswKey: SymmetricKey = try Cipher.passwordKey(password: "abc123")
let encryptedData: Data = try Cipher.encrypt(data: "hello world".data(using: .utf8)!, key: pswKey) // Decrypt payload with local shared key
let decryptedData: Data = try Cipher.decrypt(data: encryptedData, key: pswKey) // Decrypt payload with remote shared key
String(data: decryptedData, encoding: .utf8) // abc123
```
## Resources
| Topic | Link |
| --- | --- |
| Diffie hellman | [Link](https://shubhomoybiswas.medium.com/diffie-hellman-key-exchange-in-end-to-end-encryption-e2ee-2366e056661) |
| CryptoKit | [Link](https://www.raywenderlich.com/10846296-introducing-cryptokit) |
| xchacha20 | [Link](https://nordpass.com/features/xchacha20-encryption/) |
| Encrypting data with CryptoKit and custom password | [Link](https://fred.appelman.net/?p=119) |
| Common cryptographic operations in Swift with CryptoKit | [Link](https://medium.com/swlh/common-cryptographic-operations-in-swift-with-cryptokit-b30a4becc895) |


## Other Encryption Libraries
| Library | Link |
| --- | --- |
| Argon2id | [Link](https://www.cryptolux.org/images/0/0d/Argon2.pdf) |
| Blake2b | [Link](https://doc.libsodium.org/hashing/generic_hashing) |
| XChaCha20 | [Link](https://doc.libsodium.org/advanced/stream_ciphers/xchacha20) |
| Poly1305 | [Link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) |
| swift-sodium | [Link](https://github.com/jedisct1/swift-sodium) |

### Todo:
- Add more / better doc and examples
- Show how migration API would work etc
- Color decorate different chars in passwords, letter gets one color, number another, symbol another. see: https://github.com/keepassium/KeePassium/blob/master/KeePassium/util/PasswordStringHelper.swift
- Add some more doc around salt
- Add Introduction: Expand the introduction to include more details about the library. What makes it unique? Why should someone use it over other libraries? What problems does it solve?
Installation: Include a section on how to install and setup your library. This could include the commands to run, any dependencies that need to be installed, etc.
- Add Usage: Expand the examples section to include more comprehensive examples. Show how to use the library in a real-world scenario. This could include examples of how to handle errors, how to use the library in a larger project, etc.
