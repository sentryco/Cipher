import Foundation
import CryptoKit
import Logger
/**
 * Decrypt data
 * - Description: This extension provides methods for decrypting data. It 
 *                supports decryption using a symmetric key encryption scheme, 
 *                where the symmetric key can be generated from a password or 
 *                a shared key. It also supports decryption using a combination 
 *                of private and public keys. The decryption process involves 
 *                creating a sealed box from the encrypted data and then 
 *                opening it using the provided symmetric key or the combination 
 *                of private and public keys.
 * - Note: Alternate file-name: `Cipher+UnLock`
 */
extension Cipher {
   /**
    * Decrypts data using a symmetric key encryption scheme.
    * - Abstract: This encryption scheme uses a private key only, which can be 
    *             generated from a password or a shared key.
    * - Description: This method decrypts the provided data using a symmetric 
    *                key encryption scheme. The symmetric key can be generated 
    *                from a password or a shared key. The decryption process 
    *                involves creating a sealed box from the encrypted data and 
    *                then opening it using the provided symmetric key. If the 
    *                decryption process fails, an error is thrown.
    * - Remark: The private key can be read using 
    *           `Cipher.getPrivKeyData(privKey: key).base64EncodedString()`.
    * - Parameters:
    *   - data: The data to be decrypted.
    *   - key : The symmetric key to use for decryption, such as a shared key or 
    *           a `SymmetricKey(size: .bits256)`.
    * - Returns: The decrypted data.
    * - Throws : An error if the decryption process fails.
    */
   public static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
      // Log an info message to indicate that the decryption process has started.
      // - Fixme: ⚠️️ remove this probably. too much logging
      Logger.info("\(Trace.trace())", tag: .security)
      do {
         // Create a sealed box from the encrypted data.
         let sealedBox: ChaChaPoly.SealedBox = try ChaChaPoly.SealedBox(combined: data)
         return try ChaChaPoly.open( // Decrypt the sealed box using the specified key.
            sealedBox, // The sealed box to open
            using: key // The key to use for opening the sealed box
         )
      } catch {
         // If an error occurs during decryption, throw an NSError with a descriptive error message.
         throw NSError(domain: "⚠️️ Unabled to open sealedBox with key: \(key.bitCount) - error: \(error.localizedDescription)", code: 0)
      }
   }
   /**
    * Decrypts data using a combination of private and public keys.
    * - Abstract: The public key is passed as a string because it can be stored 
    *             unprotected, whereas the private key must be stored securely 
    *             (e.g. in the keychain).
    * - Description: This method decrypts the provided data using a combination 
    *                of private and public keys. The public key is passed as a 
    *                string because it can be stored unprotected, whereas the 
    *                private key must be stored securely (e.g. in the keychain). 
    *                The decryption process involves creating a shared symmetric 
    *                key using the private and public keys and the specified salt, 
    *                and then decrypting the data using this shared key. If the 
    *                decryption process fails, an error is thrown.
    *   - data: The data to decrypt.
    *   - pubKey: The public key to decrypt with in combination with the private key.
    *   - privKey: The private key to decrypt with in combination with the public key.
    *   - salt: An app-defined salt to use in the key derivation process. Use 
    *           unique salts for unique cases to prevent rainbow table attacks.
    * - Returns: The decrypted data.
    * - Throws: An error if the decryption process fails.
    */
   public static func decrypt(data: Data, pubKey: String, privKey: PrivKey, salt: Data = Cipher.defaultSalt) throws -> Data {
      // Import the public key from its string representation.
      let pubKey: PubKey = try Cipher.importPubKey(pubKey: pubKey)
      // Generate a shared symmetric key using the private and public keys and the specified salt.
      let sharedKey: SymmetricKey = try Cipher.getSharedKey(
         privKey: privKey, // The private key to use for generating the shared key
         pubKey: pubKey, // The public key to use for generating the shared key
         salt: salt // The salt to use for generating the shared key
      )
      // Decrypt the data using the shared symmetric key
      return try decrypt(
         data: data, // The data to decrypt
         key: sharedKey // The key to use for decryption
      )
   }
}
