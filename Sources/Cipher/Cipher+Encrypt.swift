import Foundation
import CryptoKit
import Logger
/**
 * Encrypt data
 * - Note: Alternate file-name: `Cipher+Lock`
 */
extension Cipher {
   /**
    * Encrypts data using a symmetric key encryption scheme
    * - Abstract: This encryption scheme uses a private key only, which can be 
    *             generated from a password or a shared key.
    * - Description: This method encrypts the provided data using a symmetric key encryption scheme. The symmetric key can be generated from a password or a shared key. The encryption process involves sealing the data using the provided symmetric key. If the encryption process fails, an error is thrown.
    * - Description: This method encrypts the provided data using a symmetric 
    *                key encryption scheme. The symmetric key can be generated 
    *                from a password or a shared key. The encryption process 
    *                involves sealing the data using the provided symmetric key. 
    *                If the encryption process fails, an error is thrown.
    * - Parameters:
    *   - data: The data to be encrypted
    *   - key: The symmetric key to use for encryption, such as a shared key or a `SymmetricKey(size: .bits256)`.
    * - Returns: The encrypted data.
    */
   public static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
      // Log an info message to indicate that the encryption process has started.
      // - Fixme: ⚠️️ Remove this probably. too much logging
      print("\(Trace.trace())")
      do {
         // Seal the data using the specified key.
         let sealedBox: ChaChaPoly.SealedBox = try ChaChaPoly.seal(
            data, // The data to seal
            using: key // The key to use for sealing the data
         )
         // Convert the sealed box to raw data.
         return sealedBox.combined
      } catch {
         // If an error occurs during encryption, throw an NSError with a descriptive error message.
         throw NSError(domain: "⚠️️ Unabled to close sealedBox with key: \(key.bitCount) - error: \(error.localizedDescription)", code: 0)
      }
   }
   /**
    * Encrypts data using a combination of private and public keys.
    * - Description: This method encrypts the provided data using a combination 
    *                of private and public keys. The public key is passed as a 
    *                string because it can be stored unprotected, whereas the 
    *                private key must be stored securely (e.g. in the keychain). 
    *                The encryption process involves creating a shared symmetric 
    *                key using the private and public keys and the specified salt, 
    *                and then encrypting the data using this shared key. If the 
    *                encryption process fails, an error is thrown.
    * - Remark: The public key is passed as a string because it can be stored 
    *           unprotected, whereas the private key must be stored securely 
    *           (e.g. in the keychain).
    * - Parameters:
    *   - data: The data to encrypt.
    *   - pubKey: The public key to encrypt with in combination with the private key.
    *   - privKey: The private key to encrypt with in combination with the public key.
    *   - salt: An app-defined salt to use in the key derivation process. Use 
    *           unique salts for unique cases to prevent rainbow table attacks.
    * - Returns: The encrypted data.
    * - Throws: An error if the encryption process fails.
    */
   public static func encrypt(data: Data, pubKey: String, privKey: PrivKey, salt: Data = defaultSalt) throws -> Data {
      // Import the public key from its string representation.
      let pubKey: PubKey = try Cipher.importPubKey(pubKey: pubKey)
      // Generate a shared symmetric key using the private and public keys and the specified salt.
      let sharedKey: SymmetricKey = try Cipher.getSharedKey(
         privKey: privKey, // The private key to use for generating the shared key
         pubKey: pubKey, // The public key to use for generating the shared key
         salt: salt // The salt to use for generating the shared key
      )
      // Encrypt the data using the shared symmetric key.
      return try encrypt(
         data: data, // The data to encrypt
         key: sharedKey // The key to use for encryption
      )
   }
}
