import Foundation
import SwiftUI
import CryptoKit
/**
 * CryptoWrapper
 * - Description: This extension provides convenience methods for encrypting 
 *                and decrypting data using the CryptoWrapper.
 */
extension CryptoWrapper {
   /**
    * Decrypts the provided data using the specified symmetric key.
    * - Abstract: This method attempts to decrypt the given data using the 
    *             ChaChaPoly algorithm and the provided symmetric key. If the 
    *             decryption process fails, it throws an error.
    * - Description: This method uses the ChaChaPoly algorithm to decrypt the 
    *                provided data with the given symmetric key. If the 
    *                decryption process fails, an error is thrown.
    * - Parameters:
    *   - data: The encrypted data to be decrypted.
    *   - key: The symmetric key used for decryption.
    * - Returns: The decrypted data.
    */
   public static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
      do {
         let sealedBox: ChaChaPoly.SealedBox = try ChaChaPoly.SealedBox(combined: data)
         return try ChaChaPoly.open(
            sealedBox,
            using: key
         )
      } catch {
         throw NSError(domain: "⚠️️ Unabled to open sealedBox with key: \(key.bitCount) - error: \(error.localizedDescription)", code: 0)
      }
   }
   /**
    * Encrypts the provided data using the specified symmetric key.
    * - Abstract: This method attempts to encrypt the given data using the 
    *             ChaChaPoly algorithm and the provided symmetric key. If the 
    *             encryption process fails, it throws an error.
    * - Description: This method uses the ChaChaPoly algorithm to encrypt the 
    *                provided data with the given symmetric key. If the 
    *                encryption process fails, an error is thrown.
    * - Parameters:
    *   - data: The data to be encrypted.
    *   - key: The symmetric key used for encryption.
    * - Returns: The encrypted data.
    */
   public static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
      do {
         // Creates a sealed box using the ChaChaPoly algorithm to encrypt the provided data with the given symmetric key.
         let sealedBox: ChaChaPoly.SealedBox = try ChaChaPoly.seal(
            data, // The data to be encrypted.
            using: key // The symmetric key used for encryption.
         )
         // Returns the combined data of the sealed box which is the encrypted data.
         return sealedBox.combined
      } catch {
         throw NSError(domain: "⚠️️ Unabled to close sealedBox with key: \(key.bitCount) - error: \(error.localizedDescription)", code: 0)
      }
   }
}
