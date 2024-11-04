import Foundation
import SwiftUI
import CryptoKit
/**
 * Key
 * - Description: This extension provides methods for generating and handling symmetric keys for cryptographic operations.
 */
extension CryptoWrapper {
   /**
    * Generates a 256-bit symmetric key for cryptographic operations.
    * - Abstract: This key is used for symmetric encryption and decryption.
    * - Description: This method generates a 256-bit symmetric key that can be 
    *                used for cryptographic operations such as encryption and 
    *                decryption. The generated key is secure and random, making 
    *                it suitable for high-security applications.
    * - Returns: A 256-bit symmetric key.
    */
   public static var privKey256: SymmetricKey {
      SymmetricKey(size: .bits256) // Generates a 256-bit symmetric key
   }
  /**
   * Converts the provided symmetric key to its raw data representation.
   * - Abstract: This method takes a symmetric key as input and returns its raw 
   *             data equivalent. This is useful for storing or transmitting the 
   *             key in a raw format.
   * - Description: This method is used to convert a symmetric key into its raw data equivalent. This is particularly useful when the key needs to be stored or transmitted in a format that is not specific to the CryptoKit framework.
   * - Description: This method is used to convert a symmetric key into its raw 
   *                data equivalent. This is particularly useful when the key 
   *                needs to be stored or transmitted in a format that is not 
   *                specific to the CryptoKit framework.
   * - Returns: The raw data representation of the symmetric key.
   */
   public static func getPrivKeyData(privKey: SymmetricKey) -> Data {
      privKey.withUnsafeBytes { Data(Array($0)) } // Converts key to raw data
   }
   /**
    * Converts raw data into a symmetric key.
    * - Abstract: This method takes raw data as input and converts it into a 
    *             symmetric key. The provided data is expected to be a valid 
    *             representation of a symmetric key, and the method returns a 
    *             SymmetricKey object created from this data. This conversion 
    *             is useful for scenarios where the key needs to be stored or 
    *             transmitted in a raw format and then converted back into a 
    *             usable symmetric key.
    * - Description: This method is used to convert raw data back into a 
    *                symmetric key. This is particularly useful when the key 
    *                has been stored or transmitted in a raw format and needs 
    *                to be converted back into a usable symmetric key for 
    *                cryptographic operations.
    * - Returns: A symmetric key created from the provided data. This key can be 
    *             used for cryptographic operations such as encryption and 
    *             decryption.
    */
   public static func getPrivKey(data: Data) -> SymmetricKey {
      SymmetricKey(data: data)
   }
}
