import XCTest
import Cipher
import CryptoKit
import Dice

final class CipherTests: XCTestCase {
   /**
    * Tests
    * - Fixme: ⚠️️ Use random salts for tests, instead of default salt etc, just to add more randomness to tests etc
    * - Fixme: ⚠️️ Add the encrypt / decrypt test that is used for the JSON DB etc? elaborate?
    */
   internal func testExample() {
      do {
         try encryptionTest() // Call the encryptionTest function and handle any errors that might be thrown
         try sharedKeyTest() // E2EE encryption / decryption tests
         try codeTesting() // Confirm code handshake tests (low-level-test)
         testCrypto() // tests cryptowrapper
      } catch {
         Swift.print("error:  \(error)")
      }
   }
}
/**
 * Tests
 */
extension CipherTests {
   /**
    * Test encryption with data and change-model
    * - Description: This test verifies the encryption and decryption process 
    *                using a symmetric key. It ensures that the data encrypted 
    *                with a private key can be successfully decrypted back to 
    *                its original form using the same key.
    * - Fixme: ⚠️️ Try to store data as string and encrypt decrypt that too
    * - Fixme: ⚠️️ To get this working in SPM unit test, this will require that we remove KeyChain appgroup for tests etc, for now we just use local privkey instead of KeyChain
    */
   fileprivate func encryptionTest() throws {
      // Swift.print("encryptionTest")
      guard let data = "123abc".data(using: .utf8) else {  // Create a Data object from a string
         XCTFail("Failed to convert string to data")
         return
      }
      let privKey: SymmetricKey = Cipher.privKey256 // Get a private key for encryption
      let encryptedData: Data = try Cipher.encrypt(data: data, key: privKey) // Encrypt the data using the private key
      let decryptedData: Data = try Cipher.decrypt(data: encryptedData, key: privKey) // Decrypt the data using the private key
      let match: Bool = data == decryptedData // Check if the decrypted data matches the original data
      Swift.print("encryptionTest - match: \(match ? "✅" : "🚫")") // Print whether the encryption and decryption were successful
      XCTAssertTrue(match) // Assert that the decrypted data matches the original data
   }
   /**
    * Tests (encrypting / decrypting) data with E2EE (priv / pub encryption between two enteties)
    * - Description: This test simulates an end-to-end encryption and decryption 
    *                process between two entities using their respective public 
    *                and private keys. It ensures that the shared symmetric key 
    *                derived from the key pairs can successfully encrypt and 
    *                decrypt a message.
    * 1. `B` Posts public key
    * 2. `A` Encrypts with B's pub key and sends message to B with A's pub key.
    * 3. `B` Decrypts message with A's pubkey and it's own priv key 🎉
    * - Fixme: ⚠️️ Replace forced unwrap by adding guards that fail tests?
    */
   fileprivate func sharedKeyTest() throws {
      // Swift.print("CipherTests.basicTests")
      let a: KeyPair = try Cipher.getKeyPair() // Create first keypair
      _ = try { // Test Import / Export privKey
         let aPrivKeyStr: String = try Cipher.exportPrivKey(privKey: a.priv) // Export the private key of the `a` object as a string and assign it to `aPrivKeyStr`
         // Swift.print("aPrivKeyStr: \(String(describing: aPrivKeyStr))")
         let aPrivKey: PrivKey = try Cipher.importPrivKey(privKey: aPrivKeyStr) // Import the private key of the `a` object from the string `aPrivKeyStr` using the `Cipher.importPrivKey` method and assign it to `aPrivKey`
         let privKeysAreEqual: Bool = a.priv.rawRepresentation == aPrivKey.rawRepresentation // Check if the raw representation of the private key of the `a` object is equal to the raw representation of the imported private key and assign the resulting boolean value to `privKeysAreEqual`
         Swift.print("privKeysAreEqual: \(privKeysAreEqual ? "✅" : "🚫")")
         XCTAssertTrue(privKeysAreEqual)
      }()
      _ = try { // Test import export pub key
         let aPubKeyStr: String = try Cipher.exportPubKey(pubKey: a.pub) // Export the public key of the `a` object as a string and assign it to `aPubKeyStr`
         // Swift.print("aPubKeyStr: \(String(describing: aPubKeyStr))")
         let aPubKey: PubKey = try Cipher.importPubKey(pubKey: aPubKeyStr) // Import the public key of the `a` object from the string `aPubKeyStr` using the `Cipher.importPubKey` method and assign it to `aPubKey`
         let pubKeysAreEqual: Bool = a.pub.rawRepresentation == aPubKey.rawRepresentation // Check if the raw representation of the public key of the `a` object is equal to the raw representation of the imported public key and assign the resulting boolean value to `pubKeysAreEqual`
         Swift.print("pubKeysAreEqual: \(pubKeysAreEqual ? "✅" : "🚫")")
         XCTAssertTrue(pubKeysAreEqual)
      }()
      let b: KeyPair = try Cipher.getKeyPair() // Create a second keypair
      let salt: Data = Cipher.randomSalt(length: 128) // Generate a random salt of length 128
      let aSharedKey: SymmetricKey = try Cipher.getSharedKey(
         privKey: a.priv, // The private key of party A
         pubKey: b.pub, // The public key of party B
         salt: salt // The salt value used to derive the shared key
      ) // Create a shared key based on the local private key of `a` and the public key of `b`, using the `Cipher.getSharedKey` method, and assign it to `aSharedKey`
      let bSharedKey: SymmetricKey = try Cipher.getSharedKey(
         privKey: b.priv, // The private key of party B
         pubKey: a.pub, // The public key of party A
         salt: salt // The salt value used to derive the shared key
      ) // Create a shared key based on the remote private key of `b` and the public key of `a`, using the `Cipher.getSharedKey` method, and assign it to `bSharedKey`
      _ = try { // Test payload test
         let encryptedData: Data = try Cipher.encrypt(
            data: "abc123".data(using: .utf8)!, // The data to encrypt
            key: aSharedKey // The shared key used to encrypt the data
         ) // Encrypt the data "abc123" using the local shared key `aSharedKey` and assign it to `encryptedData`
         let decryptedData: Data = try Cipher.decrypt(
            data: encryptedData, // The encrypted data to decrypt
            key: bSharedKey // The shared key used to decrypt the data
         ) // Decrypt the `encryptedData` using the remote shared key `bSharedKey` and assign it to `decryptedData`
         // print("Data: \(String(data: decryptedData, encoding: .utf8)!)") // abc123
         let payloadsAreEqual: Bool = String(data: decryptedData, encoding: .utf8)! == "abc123" // Check if the decrypted data is equal to the original data "abc123" and assign the resulting boolean value to `payloadsAreEqual`
         Swift.print("payloadsAreEqual: \(payloadsAreEqual ? "✅" : "🚫")")
         XCTAssertTrue(payloadsAreEqual)
      }()
   }
   /**
    * Confirm code test
    * - Description: This test verifies the encryption and decryption process 
    *                using shared keys derived from local and remote key pairs.
    * - Remark: To decrypt, the remote needs `local-pub`, and local needs `remote-pub`.
    */
   fileprivate func codeTesting() throws {
      // Swift.print("CipherTests.codeTesting()")
      let a: KeyPair = try Cipher.getKeyPair() // Create a local keypair and assign it to `a`
      let b: KeyPair = try Cipher.getKeyPair() // Create a remote keypair and assign it to `b`
      let salt: Data = Cipher.randomSalt(length: 128) // Generate a new salt of length 128 and assign it to `salt`
      Swift.print("salt:  \(salt.base64EncodedString())")
      let localSharedKey: SymmetricKey = try Cipher.getSharedKey(
         privKey: a.priv, // The private key of party A
         pubKey: b.pub, // The public key of party B
         salt: salt // The salt value used to derive the shared key
      ) // Create a shared key based on the local private key of `a` and the public key of `b`, using the `Cipher.getSharedKey` method, and assign it to `localSharedKey`
      let remoteSharedKey: SymmetricKey = try Cipher.getSharedKey(
         privKey: b.priv, // The private key of party B
         pubKey: a.pub, // The public key of party A
         salt: salt // The salt value used to derive the shared key
      ) // Create a shared key based on the remote private key of `b` and the public key of `a`, using the `Cipher.getSharedKey` method, and assign it to `remoteSharedKey`
      let code: String = try RandPSW.makeRandomWord(
         recipe: .init(
            charCount: 0, // The number of characters in the password
            numCount: 4, // The number of numbers in the password
            symCount: 0 // The number of symbols in the password
         )
      ) // Create a random 4-digit code using the `RandPSW.getRandomPassword` method and assign it to `code`. We use Dice to generate the random code. The comments describe each line of code and its purpose.
      // Swift.print("Code: \(code)")
      // Encrypt
      // guard let codeData: Data = code.data(using: .utf8) else { throw NSError(domain: "⚠️️ err - code data", code: 0) }
      guard let codeData: Data = .init(base64Encoded: code) else { Swift.print("⚠️️ err - code data"); return } // Decode the base64-encoded `code` string into a `Data` object and assign it to `codeData`. If the decoding fails, print an error message and return.
      let encryptedCodeData: Data = try Cipher.encrypt(
         data: codeData, // The data to encrypt
         key: localSharedKey // The shared key used to encrypt the data
      ) // Encrypt the `codeData` using the `localSharedKey` using the `Cipher.encrypt` method, and assign the resulting encrypted data to `encryptedCodeData`. If the encryption fails, throw an error. 
      // Decrypt
      let decryptedCodeData: Data = try Cipher.decrypt(
         data: encryptedCodeData, // The encrypted data to decrypt
         key: remoteSharedKey // The shared key used to decrypt the data
      ) // else { Swift.print("err ⚠️️ - decryptedCodeData"); return }
      // guard let decryptedCode: String = .init(data: decryptedCodeData, encoding: .utf8) else { throw NSError(domain: "err ⚠️️ - decryptedCode", code: 0) } // encrypt code, and store the encrypted data as string
      /*guard */let decryptedCode: String = decryptedCodeData.base64EncodedString() // else { Swift.print("err ⚠️️ - decryptedCode"); return } // encrypt code, and store the encrypted data as string
      // Swift.print("decryptedCode: \(decryptedCode)")
      let codesAreEqual: Bool = code == decryptedCode // check if initial code is the same as the decrypted one
      Swift.print("codesAreEqual: \(codesAreEqual ? "✅" : "🚫")")
      XCTAssertTrue(codesAreEqual)
   }
   /**
    * Test encrypting / decrypting
    * - Description: This test verifies the encryption and decryption process using 
    *                a symmetric key. It uses a predefined private key to encrypt 
    *                a string, then decrypts the encrypted data using the same 
    *                key and compares the decrypted string with the original one 
    *                to ensure the encryption and decryption process works correctly.
    * - Fixme: ⚠️️ Adding Keychain test will probably fail in terminal etc. 
    */
   func testCrypto() {
      // - Fixme: ⚠️️ add tests from legacy
      let privKey = CryptoWrapper.privKey256
      // create abc123 data
      let string = "abc123"
      if let data: Data = string.data(using: .utf8) {
         // encrypt data
         if let encryptedData = try? CryptoWrapper.encrypt(data: data, key: privKey) {
            // decrypt data
            if let decryptedData = try? CryptoWrapper.decrypt(
               data: encryptedData, // The encrypted data to be decrypted
               key: privKey // The symmetric key used for decryption
            ) {
               let str: String? = String(data: decryptedData, encoding: .utf8)
               let assert = str == string
               // assert content
               Swift.print("assert:  \(assert ? "✅" : "🚫")")
               XCTAssertTrue(assert)
            }
         }
      }
   }
}
