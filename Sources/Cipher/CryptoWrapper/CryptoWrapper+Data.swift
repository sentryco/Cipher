import Foundation
import SwiftUI
import CryptoKit
/**
 * Convenience (has logging etc)
 * - Description: This extension provides convenience methods for encrypting 
 *                and decrypting data using the CryptoWrapper.
 */
extension Data {
   /**
    * Encrypt data
    * - Abstract: This method attempts to encrypt the given data using the 
    *             ChaChaPoly algorithm and the provided symmetric key. If the 
    *             encryption process fails, it logs an error message and 
    *             returns nil.
    * - Description: This method uses the provided symmetric key to encrypt the 
    *                current instance of Data. If the key is nil or the encryption 
    *                process fails, it logs an error and returns nil.
    * - Fixme: ⚠️️ make it throw 👈 or do we use another encrypt method somewhere else?
    * - Parameter privKey: The symmetric key used for encryption.
    * - Returns: The encrypted data or nil if encryption fails.
    */
   public func encrypt(privKey: SymmetricKey?) -> Data? {
      // Check if the provided private key is not nil and can be unwrapped to a SymmetricKey
      if let privKey: SymmetricKey = privKey {
         // Attempt to encrypt the data using the provided private key
         do {
            return try CryptoWrapper.encrypt(
               data: self, // Data to encrypt
               key: privKey // Symmetric key
            ) // Call the encrypt method from CryptoWrapper
         } catch {
            // Log an error message if encryption fails
            Swift.print("⚠️️ Unable to encrypt data - err: \(error.localizedDescription)")
            return nil // Return nil to indicate encryption failure
         }
      } else {
         // Log a message if no private key is provided
         Swift.print("⚠️️ No encryption - privKey: \(String(describing: privKey))")
         return nil // Return nil to indicate no encryption attempt was made
      }
   }
   /**
    * Decrypts the data using the provided symmetric key.
    * - Abstract: This method attempts to decrypt the given data using the 
    *             ChaChaPoly algorithm and the provided symmetric key. If the 
    *             decryption process fails, it logs an error message and 
    *             returns nil.
    * - Description: This method uses the provided symmetric key to decrypt the 
    *                current instance of Data. If the key is nil or the decryption 
    *                process fails, it logs an error and returns nil.
    * - Fixme: ⚠️️ make it throw, or do we use another encrypt method somewhere else?
    * - Parameter privKey: The symmetric key used for decryption.
    * - Returns: The decrypted data or nil if decryption fails.
    */
   public func decrypt(privKey: SymmetricKey?) -> Data? {
      // Check if the provided private key is not nil and can be unwrapped to a SymmetricKey
      if let privKey: SymmetricKey = privKey {
         // Attempt to decrypt the data using the provided private key
         do {
            return try CryptoWrapper.decrypt(
               data: self, // Data to decrypt
               key: privKey // Symmetric key
            ) // Call the decrypt method from CryptoWrapper
         } catch {
            // Log an error message if decryption fails
            Swift.print("⚠️️ unable to decrypt data - err: \(error.localizedDescription)")
            return nil // Return nil to indicate decryption failure
         }
      } else {
         // Log a message if no private key is provided
         Swift.print("⚠️️ no encryption - privKey: \(String(describing: privKey))")
         return nil // Return nil to indicate no decryption attempt was made
      }
   }
}
