import XCTest
@testable import Cipher
import CryptoKit
import Dice

extension CipherTests {
   /**
    * Tests the encryption and decryption functionality using a symmetric key.
    *
    * This test ensures that data encrypted with a symmetric key
    * can be decrypted back to its original form using the same key.
    * It verifies that the encryption and decryption processes are consistent.
    */
   func testEncryptionDecryption() {
      do {
         let key = SymmetricKey(size: .bits256)
         let originalData = "Sensitive data".data(using: .utf8)!
         let encryptedData = try Cipher.encrypt(data: originalData, key: key)
         let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)
         XCTAssertEqual(originalData, decryptedData, "Decrypted data does not match the original")
      } catch {
         XCTFail("Encryption/Decryption failed with error: \(error)")
      }
   }
}
// Test Encryption and Decryption with Different Data Types
// Verify that the encryption and decryption functions work correctly with various data types such as strings, JSON objects, and binary data.
extension CipherTests {
   /**
    * Tests encryption and decryption of a simple string using a symmetric key.
    *
    * This test encrypts a string, then decrypts it, and verifies that the decrypted string matches the original.
    *
    * - Throws: An error if encryption or decryption fails.
    */
   func testEncryptDecryptString() throws {
      let originalString = "Test String"
      let data = originalString.data(using: .utf8)!
      let key = SymmetricKey(size: .bits256)
      
      let encryptedData = try Cipher.encrypt(data: data, key: key)
      let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)
      let decryptedString = String(data: decryptedData, encoding: .utf8)
      
      XCTAssertEqual(originalString, decryptedString, "Decrypted string does not match the original")
   }
   /**
    * Tests encryption and decryption of a JSON object using a symmetric key.
    *
    * This test serializes a JSON object to data, encrypts it, decrypts it, and then deserializes the data back to a JSON object.
    * It verifies that the decrypted JSON object matches the original.
    *
    * - Throws: An error if serialization, encryption, decryption, or deserialization fails.
    */
   func testEncryptDecryptJSON() throws {
      let jsonObject: [String: Any] = ["key": "value", "number": 42]
      let data = try JSONSerialization.data(withJSONObject: jsonObject, options: [])
      let key = SymmetricKey(size: .bits256)
      
      let encryptedData = try Cipher.encrypt(data: data, key: key)
      let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)
      let decryptedObject = try JSONSerialization.jsonObject(with: decryptedData, options: []) as? [String: Any]
      
      XCTAssertEqual(jsonObject as NSDictionary, decryptedObject! as NSDictionary, "Decrypted JSON does not match the original")
   }
   /**
    * Tests encryption and decryption of binary data using a symmetric key.
    *
    * This test generates random binary data, encrypts it, decrypts it, and verifies that the decrypted data matches the original.
    *
    * - Throws: An error if encryption or decryption fails.
    */
   func testEncryptDecryptBinary() throws {
      let originalData = Data((0..<256).map { _ in UInt8.random(in: 0...255) })
      let key = SymmetricKey(size: .bits256)

      let encryptedData = try Cipher.encrypt(data: originalData, key: key)
      let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)

      XCTAssertEqual(originalData, decryptedData, "Decrypted data does not match the original")
   }
}
// Test Key Export and Import
// Ensure that exporting and importing private and public keys work correctly and that the re-imported keys are equal to the original keys.
extension CipherTests {
   /**
    * Tests the export and import functionality for private keys.
    *
    * This test ensures that a private key can be exported to a string format and imported back,
    * resulting in a key that is identical to the original. It verifies that the serialization
    * and deserialization processes for private keys work correctly.
    *
    * - Throws: An error if key generation, export, or import fails.
    */
   func testPrivateKeyExportImport() throws {
      let originalKeyPair = try Cipher.getKeyPair()
      let exportedPrivKey = try Cipher.exportPrivKey(privKey: originalKeyPair.priv)
      let importedPrivKey = try Cipher.importPrivKey(privKey: exportedPrivKey)
      
      XCTAssertEqual(originalKeyPair.priv.rawRepresentation, importedPrivKey.rawRepresentation, "Imported private key does not match the original")
   }
   /**
    * Tests the export and import functionality for public keys.
    *
    * This test ensures that a public key can be exported to a string format and imported back,
    * resulting in a key that is identical to the original. It verifies that the serialization
    * and deserialization processes for public keys work correctly.
    *
    * - Throws: An error if key generation, export, or import fails.
    */
   func testPublicKeyExportImport() throws {
      let originalKeyPair = try Cipher.getKeyPair()
      let exportedPubKey = try Cipher.exportPubKey(pubKey: originalKeyPair.pub)
      let importedPubKey = try Cipher.importPubKey(pubKey: exportedPubKey)
      
      XCTAssertEqual(originalKeyPair.pub.rawRepresentation, importedPubKey.rawRepresentation, "Imported public key does not match the original")
   }
}
// Test Encryption and Decryption with Password-Based Key
// Verify that encryption and decryption using a password-derived key work correctly.
extension CipherTests {
   /**
    * Tests encryption and decryption using a password-derived key.
    *
    * This test verifies that data encrypted using a key derived from a password
    * can be decrypted successfully using the same password. It ensures that the
    * password-based key derivation and symmetric encryption/decryption processes
    * function correctly.
    *
    * - Throws: An error if key derivation, encryption, or decryption fails.
    */
   func testPasswordBasedEncryption() throws {
      let password = "StrongPassword123!"
      let data = "Sensitive data".data(using: .utf8)!
      let key = try Cipher.getPasswordKey(password: password)
      
      let encryptedData = try Cipher.encrypt(data: data, key: key)
      let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)
      let decryptedString = String(data: decryptedData, encoding: .utf8)
      
      XCTAssertEqual("Sensitive data", decryptedString, "Decrypted data does not match the original")
   }
   /**
    * Tests decryption with an incorrect password-derived key.
    *
    * This test verifies that attempting to decrypt data using a key derived from
    * an incorrect password results in a failure. It ensures that encryption using
    * password-derived keys is secure and that the data cannot be decrypted without
    * the correct password.
    *
    * - Throws: An error if key derivation or encryption fails.
    */
   func testIncorrectPassword() throws {
      let correctPassword = "CorrectPassword"
      let incorrectPassword = "IncorrectPassword"
      let data = "Sensitive data".data(using: .utf8)!
      let correctKey = try Cipher.getPasswordKey(password: correctPassword)
      let incorrectKey = try Cipher.getPasswordKey(password: incorrectPassword)
      
      let encryptedData = try Cipher.encrypt(data: data, key: correctKey)
      
      // Assert that decryption with the incorrect key throws an error
      XCTAssertThrowsError(try Cipher.decrypt(data: encryptedData, key: incorrectKey), "Decryption should fail with incorrect password")
   }
}
// Test Generating and Using Shared Keys for End-to-End Encryption
// Confirm that both parties can generate a shared key and use it to encrypt and decrypt messages correctly.
extension CipherTests {
   /**
    * Tests end-to-end encryption using shared keys between two parties.
    *
    * This test simulates two parties, A and B, generating their own key pairs and
    * computing a shared symmetric key using each other's public keys and their own private keys.
    * It verifies that both parties derive the same shared key and can encrypt and decrypt
    * messages using that shared key, ensuring the correct implementation of the Diffie-Hellman
    * key exchange mechanism.
    *
    * Steps:
    * 1. Party A and B generate their own key pairs.
    * 2. Both compute the shared key using their own private key and the other party's public key.
    * 3. Verify that both shared keys are equal.
    * 4. Party A encrypts a message using the shared key.
    * 5. Party B decrypts the message using the shared key.
    * 6. Verify that the decrypted message matches the original.
    *
    * - Throws: An error if key generation, shared key computation, encryption, or decryption fails.
    */
   func testSharedKeyEncryption() throws {
         // Party A generates a key pair
         let aKeyPair = try Cipher.getKeyPair()
         // Party B generates a key pair
         let bKeyPair = try Cipher.getKeyPair()

         let salt = Cipher.randomSalt(length: 32)

         // Party A computes the shared key using their private key and B's public key
         let aSharedKey = try Cipher.getSharedKey(privKey: aKeyPair.priv, pubKey: bKeyPair.pub, salt: salt)
         // Party B computes the shared key using their private key and A's public key
         let bSharedKey = try Cipher.getSharedKey(privKey: bKeyPair.priv, pubKey: aKeyPair.pub, salt: salt)

         // Assert that both shared keys are equal
         XCTAssertEqual(aSharedKey.withUnsafeBytes { Data($0) }, bSharedKey.withUnsafeBytes { Data($0) }, "Shared keys do not match")

         // Test message encryption and decryption
         let message = "Hello, secure world!".data(using: .utf8)!

         // Party A encrypts the message
         let encryptedData = try Cipher.encrypt(data: message, key: aSharedKey)
         // Party B decrypts the message
         let decryptedData = try Cipher.decrypt(data: encryptedData, key: bSharedKey)
         let decryptedMessage = String(data: decryptedData, encoding: .utf8)

         XCTAssertEqual("Hello, secure world!", decryptedMessage, "Decrypted message does not match the original")
      }
}
// Test Error Handling with Invalid Inputs
// Verify that the functions throw appropriate errors when provided with invalid inputs.
extension CipherTests {
   /**
    * Tests decryption with an invalid key.
    *
    * This test ensures that attempting to decrypt data with an incorrect symmetric key results in an error. It verifies that decryption fails when using a key different from the one used for encryption, which is essential for data security.
    *
    * - Throws: An error if encryption fails.
    */
   func testDecryptWithInvalidKey() throws {
       let data = "Test Data".data(using: .utf8)!
       let key = SymmetricKey(size: .bits256)
       let invalidKey = SymmetricKey(size: .bits256)

       let encryptedData = try Cipher.encrypt(data: data, key: key)

       // Assert that an error is thrown when decrypting with an invalid key
       XCTAssertThrowsError(try Cipher.decrypt(data: encryptedData, key: invalidKey), "Decryption should fail with invalid key")
   }
   /**
    * Tests encryption and decryption with empty data.
    *
    * This test verifies that encrypting and decrypting an empty `Data` object works correctly. It ensures that the encryption functions can handle empty inputs without errors and that the decrypted data matches the original empty data.
    *
    * - Throws: An error if encryption or decryption fails.
    */
   func testEncryptWithEmptyData() throws {
       let data = Data()
       let key = SymmetricKey(size: .bits256)

       // Test that encryption and decryption work correctly with empty data
       let encryptedData = try Cipher.encrypt(data: data, key: key)
       let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)

       XCTAssertEqual(decryptedData, data, "Decrypted data should match the original empty data")
   }
   /**
    * Tests decryption with corrupted encrypted data.
    *
    * This test ensures that decrypting data that has been tampered with results in an error. It simulates data corruption by modifying the encrypted data and verifies that decryption fails, which is important for detecting data integrity issues.
    *
    * - Throws: An error if encryption fails.
    */
   func testDecryptWithCorruptedData() throws {
       let data = "Test Data".data(using: .utf8)!
       let key = SymmetricKey(size: .bits256)
   
       var encryptedData = try Cipher.encrypt(data: data, key: key)
       // Corrupt the encrypted data by inverting the first byte
       encryptedData[0] = ~encryptedData[0]
   
       XCTAssertThrowsError(try Cipher.decrypt(data: encryptedData, key: key), "Decryption should fail with corrupted data") { error in
           // Assert that an error was thrown
           XCTAssertNotNil(error, "An error should have been thrown")
           // Optionally, print the error for debugging
           // print("Caught error: \(error)")
       }
   }
}
// Test Random Salt Generation
// Ensure that the randomSalt(length:) method generates salts of the correct length and randomness.

extension CipherTests {
   /**
    * Tests that the generated salt has the correct length.
    *
    * This test verifies that the `Cipher.randomSalt(length:)` method generates a salt with the specified length. It ensures that the salt length meets the requirements for cryptographic operations.
    */
   func testRandomSaltLength() {
       let length = 64
       let salt = Cipher.randomSalt(length: length)

       XCTAssertEqual(salt.count, length, "Generated salt does not have the correct length")
   }
   /**
    * Tests that each generated salt is unique.
    *
    * This test ensures that multiple calls to `Cipher.randomSalt(length:)` produce different salts. It checks the randomness of the salt generation, which is crucial for security to prevent attackers from predicting the salts.
    */
   func testRandomSaltUniqueness() {
       let salt1 = Cipher.randomSalt(length: 64)
       let salt2 = Cipher.randomSalt(length: 64)

       XCTAssertNotEqual(salt1, salt2, "Generated salts should be unique")
   }
}

// Test Symmetric Key Equality
// Verify that symmetric keys generated from the same password are equal and those from different passwords are not.
extension CipherTests {
   /**
    * Tests that keys derived from the same password are equal.
    *
    * This test verifies that when using the `Cipher.getPasswordKey(password:)` method with the same password, the derived symmetric keys are equal. This ensures consistent key derivation, which is critical for encryption and decryption processes that rely on password-derived keys.
    *
    * - Throws: An error if key derivation fails.
    */
   func testKeysFromSamePassword() throws {
      let password = "SamePassword"
      let key1 = try Cipher.getPasswordKey(password: password)
      let key2 = try Cipher.getPasswordKey(password: password)
      
      XCTAssertEqual(key1.withUnsafeBytes { Data($0) }, key2.withUnsafeBytes { Data($0) }, "Keys derived from the same password should be equal")
   }
   /**
    * Tests that keys derived from different passwords are not equal.
    *
    * This test ensures that when using the `Cipher.getPasswordKey(password:)` method with different passwords, the derived symmetric keys are not equal. This verifies that the key derivation function produces unique keys for different inputs, which is essential for security.
    *
    * - Throws: An error if key derivation fails.
    */
   func testKeysFromDifferentPasswords() throws {
      let key1 = try Cipher.getPasswordKey(password: "Password1")
      let key2 = try Cipher.getPasswordKey(password: "Password2")
      
      XCTAssertNotEqual(key1.withUnsafeBytes { Data($0) }, key2.withUnsafeBytes { Data($0) }, "Keys derived from different passwords should not be equal")
   }
}

// Test Key Derivation Function Parameters
// Ensure that changing the salt or parameters in key derivation affects the generated key, which is essential for security.
extension CipherTests {
   /**
    * Tests that changing the salt affects the derived shared key.
    *
    * This test verifies that when deriving shared symmetric keys using the same key pair but different salts, the resulting keys are different. This highlights the importance of using unique salts in key derivation to enhance security by preventing keys from being the same even with the same key pair.
    *
    * - Throws: An error if key derivation fails.
    */
   func testDifferentSaltsProduceDifferentKeys() throws {
      // Generate a key pair once
      let keyPair = try Cipher.getKeyPair()
      let privKey = keyPair.priv
      let pubKey = keyPair.pub
      
      // Generate two different salts
      let salt1 = Cipher.randomSalt(length: 32)
      let salt2 = Cipher.randomSalt(length: 32)
      
      // Derive shared keys with different salts
      let key1 = try Cipher.getSharedKey(privKey: privKey, pubKey: pubKey, salt: salt1)
      let key2 = try Cipher.getSharedKey(privKey: privKey, pubKey: pubKey, salt: salt2)
      
      // Compare the derived keys to ensure they are different
      XCTAssertNotEqual(key1.withUnsafeBytes { Data($0) }, key2.withUnsafeBytes { Data($0) }, "Keys derived with different salts should not be equal")
   }
}

// Test Exporting and Importing Encrypted Data
// Verify that data encrypted and exported can be imported and decrypted correctly.
extension CipherTests {
   /**
    * Tests exporting and importing encrypted data.
    *
    * This test verifies that data encrypted and exported using `Cipher.exportData(password:url:data:)` can be imported and decrypted correctly using `Cipher.importData(password:data:)`. It ensures that the encryption and decryption processes are consistent and data integrity is maintained during the export-import cycle.
    *
    * - Throws: An error if encryption, decryption, or file operations fail.
    */
   func testDataExportImport() throws {
      let password = "ExportImportPassword"
      let data = "Data to be exported".data(using: .utf8)!
      let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent("testData.dat")
      
      try Cipher.exportData(password: password, url: fileURL, data: data)
      let encryptedData = try Data(contentsOf: fileURL)
      let decryptedData = try Cipher.importData(password: password, data: encryptedData)
      let decryptedString = String(data: decryptedData, encoding: .utf8)
      
      XCTAssertEqual("Data to be exported", decryptedString, "Decrypted data does not match the original")
   }
}

// Test Key Pair Generation Validity
// Ensure that generated key pairs are valid and can be used for encryption and decryption.
extension CipherTests {
   /**
    * Tests the validity of generated key pairs.
    *
    * This test ensures that the key pairs generated by `Cipher.getKeyPair()` are valid, meaning that the private and public keys are not nil and can be used for encryption and decryption operations.
    *
    * - Throws: An error if key pair generation fails.
    */
   func testKeyPairValidity() throws {
      let keyPair = try Cipher.getKeyPair()
      XCTAssertNotNil(keyPair.priv, "Private key should not be nil")
      XCTAssertNotNil(keyPair.pub, "Public key should not be nil")
   }
}
// Test Encryption and Decryption with Empty Inputs

extension CipherTests {
    /**
     * Tests encryption and decryption with empty data.
     *
     * This test ensures that encrypting and decrypting empty data does not cause any errors
     * and that the decrypted data is also empty.
     *
     * - Throws: An error if encryption or decryption fails unexpectedly.
     */
    func testEncryptDecryptEmptyData() throws {
        let key = SymmetricKey(size: .bits256)
        let emptyData = Data()

        let encryptedData = try Cipher.encrypt(data: emptyData, key: key)
        let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)

        XCTAssertEqual(decryptedData, emptyData, "Decrypted data should match the original empty data")
    }
}
 

// Test Encryption and Decryption with Maximum and Minimum Input Sizes

extension CipherTests {
    /**
     * Tests encryption and decryption with minimum input size (empty data).
     *
     * This test ensures that encrypting and decrypting empty data works as expected.
     *
     * - Throws: An error if encryption or decryption fails.
     */
    func testEncryptDecryptMinimumSizeData() throws {
        // Reuse the testEncryptDecryptEmptyData test
        try testEncryptDecryptEmptyData()
    }

    /**
     * Tests encryption and decryption with maximum input size.
     *
     * This test ensures that encrypting and decrypting a large amount of data works as expected.
     *
     * - Throws: An error if encryption or decryption fails.
     */
    func testEncryptDecryptMaximumSizeData() throws {
        let key = SymmetricKey(size: .bits256)

        // Generate a large data buffer, e.g., 10MB of data
        let maximumSize = 10 * 1024 * 1024 // 10 MB
        let largeData = Data(count: maximumSize)

        let encryptedData = try Cipher.encrypt(data: largeData, key: key)
        let decryptedData = try Cipher.decrypt(data: encryptedData, key: key)

        XCTAssertEqual(decryptedData, largeData, "Decrypted data should match the original large data")
    }
}

