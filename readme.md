[![Tests](https://github.com/sentryco/Cipher/actions/workflows/Tests.yml/badge.svg)](https://github.com/sentryco/Cipher/actions/workflows/Tests.yml)
[![codebeat badge](https://codebeat.co/badges/defeb515-78e7-4a29-a4f1-6f58191ace4c)](https://codebeat.co/projects/github-com-sentryco-cipher-main)

# Cipher 🔏

> A Swift Encryption Library Simplifying CryptoKit

Cipher is a Swift encryption library that acts as a simplified wrapper around Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit). It streamlines cryptographic operations, making it easier for developers to implement robust encryption without delving into the complexities of cryptography. With Cipher, you can effortlessly generate key pairs, create shared keys for end-to-end encryption, and encrypt and decrypt data using password-derived keys.

## Table of Contents

- [Cipher 🔏](#cipher-)
  - [Why Cipher?](#why-cipher)
  - [Key Features](#key-features)
  - [Installation](#installation)
  - [Examples](#examples)
    - [Generating Keys](#generating-keys)
    - [Creating a Shared Key for End-to-End Encryption](#creating-a-shared-key-for-end-to-end-encryption)
    - [Encrypting and Decrypting Data with a Password](#encrypting-and-decrypting-data-with-a-password)
    - [Real-World Scenario: Secure Messaging](#real-world-scenario-secure-messaging)
    - [Exporting and Importing Keys](#exporting-and-importing-keys)
    - [Working with Salt](#working-with-salt)
  - [Cryptographic Best Practices](#cryptographic-best-practices)
  - [Resources](#resources)
  - [Other Encryption Libraries](#other-encryption-libraries)
    - [Related Encryption Libraries](#related-encryption-libraries)
  - [Todo](#todo)

**Why Cipher?**

- **Simplicity**: Cipher provides an easy-to-use API that abstracts away the complexities of cryptography.
- **Security**: Built on top of CryptoKit, Cipher ensures your encryption follows industry best practices.
- **Comprehensive Features**: From key generation to secure messaging, Cipher covers a wide range of cryptographic needs.


## Key Features

- 🔑 **Key Generation**: Generate symmetric and asymmetric keys for encryption and decryption.
- 🔒 **Data Encryption and Decryption**: Securely encrypt and decrypt data using symmetric keys.
- 🔄 **End-to-End Encryption**: Utilize Diffie-Hellman key agreement to create shared keys for secure communication.
- 🔐 **Password-Based Encryption**: Encrypt and decrypt data using a password-derived key.
- 📤 **Key Export and Import**: Easily export and import keys for storage or transmission.
- 🤖 **User-Friendly API**: Simplifies cryptographic operations with an intuitive interface.

## Installation

To integrate Cipher into your Xcode project using Swift Package Manager, add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/sentryco/Cipher.git", from: "1.0.0")
]
```

Alternatively, you can add it directly through Xcode:

1. Go to **File** > **Add Packages...**
2. Enter the repository URL: `https://github.com/sentryco/Cipher.git`
3. Select the desired version and click **Add Package**.

## Examples

### Generating Keys

Generate a new key pair (private and public keys):

```swift
import Cipher

do {
    let keyPair = try Cipher.keyPair()
    let privateKey = keyPair.privateKey
    let publicKey = keyPair.publicKey
} catch {
    print("Failed to generate key pair: \(error)")
}
```

### Creating a Shared Key for End-to-End Encryption

Create a shared symmetric key using your private key and the recipient's public key:

```swift
do {
    let sharedKey = try Cipher.sharedKey(privateKey: myPrivateKey, publicKey: recipientPublicKey)
} catch {
    print("Failed to create shared key: \(error)")
}
```

### Encrypting and Decrypting Data with a Password

Encrypt and decrypt data using a password-derived key:

```swift
do {
    // Derive key from password
    let passwordKey = try Cipher.passwordKey(password: "your_secure_password")
    
    // Encrypt data
    let messageData = "Sensitive information".data(using: .utf8)!
    let encryptedData = try Cipher.encrypt(data: messageData, key: passwordKey)
    
    // Decrypt data
    let decryptedData = try Cipher.decrypt(data: encryptedData, key: passwordKey)
    let message = String(data: decryptedData, encoding: .utf8)
    
    print(message) // Outputs: Sensitive information
} catch {
    print("Encryption/Decryption error: \(error)")
}
```

### Real-World Scenario: Secure Messaging

Implementing secure messaging between users:

```swift
// User A generates key pair
let userAKeyPair = try Cipher.keyPair()
let userAPrivateKey = userAKeyPair.privateKey
let userAPublicKey = userAKeyPair.publicKey

// User B generates key pair
let userBKeyPair = try Cipher.keyPair()
let userBPrivateKey = userBKeyPair.privateKey
let userBPublicKey = userBKeyPair.publicKey

// Exchange public keys between User A and User B

// User A creates shared key
let sharedKeyA = try Cipher.sharedKey(privateKey: userAPrivateKey, publicKey: userBPublicKey)

// User B creates shared key
let sharedKeyB = try Cipher.sharedKey(privateKey: userBPrivateKey, publicKey: userAPublicKey)

// User A encrypts a message
let originalMessage = "Hello, User B!".data(using: .utf8)!
let encryptedMessage = try Cipher.encrypt(data: originalMessage, key: sharedKeyA)

// User B decrypts the message
let decryptedMessageData = try Cipher.decrypt(data: encryptedMessage, key: sharedKeyB)
let decryptedMessage = String(data: decryptedMessageData, encoding: .utf8)
print(decryptedMessage) // Outputs: Hello, User B!
```
 
### Exporting and Importing Keys

You can export and import keys to facilitate key migration or storage:

```swift
import Cipher

do {
    // Generate a key pair
    let keyPair = try Cipher.keyPair()
    let privateKey = keyPair.privateKey
    let publicKey = keyPair.publicKey

    // Export private key to a string
    let privateKeyString = try Cipher.exportPrivKey(privKey: privateKey)

    // Import private key from a string
    let importedPrivateKey = try Cipher.importPrivKey(privKey: privateKeyString)

    // Export public key to a string
    let publicKeyString = try Cipher.exportPubKey(pubKey: publicKey)

    // Import public key from a string
    let importedPublicKey = try Cipher.importPubKey(pubKey: publicKeyString)

    // Verify that the keys match
    assert(privateKey.rawRepresentation == importedPrivateKey.rawRepresentation)
    assert(publicKey.rawRepresentation == importedPublicKey.rawRepresentation)
} catch {
    print("Key migration error: \(error)")
}
```

### Working with Salt

Salt is critical in cryptographic operations to prevent rainbow table attacks and ensure the uniqueness of derived keys.

```swift
import Cipher

// Generate a random salt of 128 bytes
let salt = Cipher.randomSalt(length: 128)

// Use the salt in key derivation or encryption operations
do {
    let sharedKey = try Cipher.sharedKey(privateKey: myPrivateKey, publicKey: recipientPublicKey, salt: salt)
} catch {
    print("Failed to create shared key: \(error)")
}
```

**Best Practices**:

- Use a unique salt for each encryption operation.
- Store or transmit the salt securely alongside the ciphertext.
- Avoid using predictable or static values for the salt.
```

> **Note**: Ensure the salt is stored or transmitted securely alongside the ciphertext for decryption.


## Cryptographic Best Practices

Cipher follows cryptographic best practices to ensure data security:

- **Authenticated Encryption**: Uses modes like ChaCha20-Poly1305 to provide confidentiality and integrity.
- **Secure Key Sizes**: Employs appropriate key sizes (e.g., 256-bit symmetric keys).
- **Key Derivation Functions**: Utilizes secure KDFs with appropriate salts and iteration counts.
- **Secure Randomness**: Generates keys and salts using secure random number generation.

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

### Related encryption libs:

- CryptoSwift: https://github.com/krzyzanowskim/CryptoSwift
- Swift Crypto: https://github.com/apple/swift-crypto
- SwiftRSA: https://github.com/puretears/SwiftRSA
- RNCryptor: https://github.com/RNCryptor/RNCryptor
- DRACOON Swift Crypto SDK: https://github.com/dracoon/dracoon-swift-crypto-sdk
 
### Todo:
- Add more / better doc and examples
- Show how migration API would work etc
- Add some more doc around salt
- Add Introduction: Expand the introduction to include more details about the library. What makes it unique? Why should someone use it over other libraries? What problems does it solve?
Installation: Include a section on how to install and setup your library. This could include the commands to run, any dependencies that need to be installed, etc.
- Add Usage: Expand the examples section to include more comprehensive examples. Show how to use the library in a real-world scenario. This could include examples of how to handle errors, how to use the library in a larger project, etc.
 - Provide an in-depth explanation of what salt is and its role in cryptography.
- Discuss how Cipher handles salt and any methods available for salt generation.
- Emphasize best practices and common pitfalls.
