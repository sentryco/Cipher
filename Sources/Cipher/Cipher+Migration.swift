import Foundation
import CryptoKit
import FileSugar
/**
 * Migration (import / export, private-key)
 */
extension Cipher {
   /**
    * Exports a private key to a raw string representation
    * - Abstract: This function is useful for storing the private key in a 
    *             secure location, such as the keychain.
    * - Description: This method allows for the secure export of a private key 
    *                by converting it into a base64-encoded string. This string 
    *                can then be stored or transmitted securely and later 
    *                converted back into a private key object using the 
    *                corresponding import method.
    * - Remark: To support percent encoding, use: 
    *           `privKeyBase64.addingPercentEncoding(withAllowedCharacters: 
    *           .alphanumerics)`.
    * - Parameter privKey: The private key to export
    * - Returns: The string representation of the private key
    */
   public static func exportPrivKey(privKey: PrivKey) throws -> String {
      // Convert the private key to raw data
      let rawPrivateKey: Data = privKey.rawRepresentation
      // Convert the raw data to a base64-encoded string
      let privKeyBase64: String = rawPrivateKey.base64EncodedString()
      // Return the private key as a base64-encoded string
      return privKeyBase64
   }
   /**
    * Imports a private key from a raw string representation
    * - Description: This method allows for the secure import of a private key 
    *                by converting a base64-encoded string back into a private 
    *                key object. This is useful when a private key needs to be 
    *                reconstructed from its string representation, which may 
    *                have been previously exported and stored securely.
    * - Remark: This function is useful for retrieving the private key from a 
    *           secure location, such as the keychain.
    * - Remark: To support percent encoding, use: `privKey.removingPercentEncoding()`
    * - Parameter privKey: The raw string representation of the private key
    * - Returns: The private key object
    * - Throws: An error if the private key cannot be imported
    */
   public static func importPrivKey(privKey: String) throws -> PrivKey {
      // Convert the base64-encoded private key string to raw data.
      guard let rawPrivateKey: Data = .init(base64Encoded: privKey) else {
         throw NSError(domain: "Err ⚠️️ data", code: 0)
      }
      // Convert the raw data to a private key object
      return try PrivKey(rawRepresentation: rawPrivateKey)
   }
}
/**
 * Migration (import / export, public key)
 */
extension Cipher {
   /**
    * Exports a public key to a raw string representation
    * - Description: This method allows for the secure export of a public key 
    *                by converting it into a base64-encoded string. This string 
    *                can then be stored or transmitted securely and later 
    *                converted back into a public key object using the 
    *                corresponding import method.
    * - Remark: This function is useful for broadcasting the public key, in 
    *           order for others to form a shared key, verify signatures, etc.
    * - Remark: We're percent-encoding the public key after encoding to base64 
    *           to ensure the `+` sign is not ignored in case the public key is 
    *           used in the URLs of specific requests.
    * - Remark: To support percent encoding, use: 
    *           `base64PublicKey.addingPercentEncoding(withAllowedCharacters: 
    *           .alphanumerics)`.
    * - Parameter pubKey: The public key to export
    * - Returns: The string representation of the public key
    */
   public static func exportPubKey(pubKey: PubKey) throws -> String {
      // Convert the public key to raw data
      let rawPublicKey: Data = pubKey.rawRepresentation
      // Convert the raw data to a base64-encoded string
      let base64PublicKey: String = rawPublicKey.base64EncodedString()
      // Return the public key as a base64-encoded string
      return base64PublicKey
   }
   /**
    * Imports a public key from a raw string representation
    * - Description: This method allows for the secure import of a public key 
    *                by converting a base64-encoded string back into a public 
    *                key object. This is useful when a public key needs to be 
    *                reconstructed from its string representation, which may 
    *                have been previously exported and stored securely.
    * - Remark: This function is useful for retrieving the public key from a 
    *           broadcasted location, such as a URL.
    * - Remark: To support percent encoding, use: `pubKey.removingPercentEncoding()`
    * - Parameter pubKey: The raw string representation of the public key
    * - Returns: The public key object
    * - Throws: An error if the public key cannot be imported
    */
   public static func importPubKey(pubKey: String) throws -> PubKey {
      // Convert the base64-encoded public key string to raw data.
      guard let rawPublicKey: Data = .init(base64Encoded: pubKey) else {
         throw NSError(domain: "Err ⚠️️ data", code: 0)
      }
      // Convert the raw data to a public key object.
      return try PubKey(rawRepresentation: rawPublicKey)
   }
}
/**
 * File export / import with encryption
 */
extension Cipher {
   /**
    * Encrypts data with an optional password and saves it to disk
    * - Description: This method encrypts the provided data using a symmetric 
    *                key encryption scheme. The symmetric key can be generated 
    *                from a password or a shared key. The encryption process 
    *                involves sealing the data using the provided symmetric key. 
    *                If the encryption process fails, an error is thrown.
    * - Remark: This function is used to securely store sensitive data on disk
    * - Remark: Make sure to use a strong password to protect the data. Strong 
    *           passwords are less likely to be broken with brute force attacks.
    * - Note: Related: https://fred.appelman.net/?p=119
    * - Note: Related: https://gist.github.com/hfossli/7165dc023a10046e2322b0ce74c596f8
    * - Parameters:
    *   - password: The password to lock the data to. Leave empty for no password protection
    *   - url: The file path to where the data should be saved
    *   - data: The data to be encrypted and saved
    * - Throws: An error if the encryption or file write process fails
    */
   public static func exportData(password: String, url: URL, data: Data) throws {
      // Encrypt the data using the specified password.
      let encryptedData: Data = try exportData(
         password: password, // The password to use for exporting the data
         data: data // The data to export
      )
      // Write the encrypted data to the specified file path
      FileModifier.write(
         path: url.path, // The path to the file to write to
         data: encryptedData // The encrypted data to write to the file
      )
   }
   /**
    * Export data with password protection
    * - Description: This function encrypts the provided data using a symmetric 
    *                key encryption scheme. The symmetric key is generated from 
    *                the provided password. The encryption process involves 
    *                sealing the data using the symmetric key. If the encryption 
    *                process fails, an error is thrown. The encrypted data is 
    *                then returned.
    * - Note: This function takes in a password and data to be locked
    * - Note: The data will be encrypted using a secure cipher algorithm and the 
    *         password will be required to unlock it.
    * - Parameters:
    *   - password: The password to lock the data. Must be at least 8 characters 
    *                long and contain at least one uppercase letter, one 
    *                lowercase letter, one number, and one special character.
    *   - data: The data to be locked. Must not be empty
    * - Returns: The locked data as a byte array
    * - Throws: An error if the password is invalid or encryption fails
    */
   public static func exportData(password: String, data: Data) throws -> Data {
      // Check if the password is not empty.
      guard !password.isEmpty else {
         throw NSError(domain: "Err ⚠️️ PSW is empty", code: 0)
      }
      // Generate a symmetric key from the password using the SHA256 hash function.
      let key: SymmetricKey = try Cipher.getPasswordKey(password: password)
      // Encrypt the data using the symmetric key
      return try Cipher.encrypt(
         data: data, // The data to encrypt
         key: key // The key to use for encryption
      )
   }
   /**
    * Decrypts data with a password.
    * - Description: This function decrypts the provided data using a symmetric 
    *                key encryption scheme. The symmetric key is generated from 
    *                the provided password. The decryption process involves 
    *                opening the sealed box using the symmetric key. If the 
    *                decryption process fails, an error is thrown. The decrypted 
    *                data is then returned.
    * - Note: This function takes in a password and encrypted data to be unlocked.
    * - Note: The data will be decrypted using a secure cipher algorithm and 
    *         the password will be required to unlock it.
    * - Parameters:
    *   - password: The password to unlock the data. Must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.
    *   - data: The encrypted data to be unlocked. Must not be empty
    * - Returns: The unlocked data as a byte array
    * - Throws: An error if the password is invalid or decryption fails
    */
   public static func importData(password: String, data: Data) throws -> Data {
      // Check if the password is not empty.
      guard !password.isEmpty else {
         throw NSError(domain: "Err ⚠️️ Password is empty", code: 0)
      }
      // Generate a symmetric key from the password using the SHA256 hash function.
      let key: SymmetricKey = try Cipher.getPasswordKey(password: password)
      // Decrypt the data using the symmetric key.
      return try Cipher.decrypt(
         data: data, // The data to decrypt
         key: key // The key to use for decryption
      )
   }
}
