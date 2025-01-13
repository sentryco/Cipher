import Foundation
import CryptoKit
/**
 * Getter
 */
extension Cipher {
   /**
    * This function is used in the "shared-key-scheme" encryption scheme
    * - Abstract: Generates a new key pair consisting of a private and public 
    *             key using the Elliptic Curve Digital Signature Algorithm 
    *             (ECDSA).
    * - Description: This function generates a new key pair for cryptographic 
    *                operations. The key pair consists of a private key and a 
    *                public key, both of which are essential for asymmetric 
    *                encryption schemes. The private key is kept secret and is 
    *                used to decrypt data, while the public key is shared openly 
    *                and is used to encrypt data. The keys are generated using 
    *                the Elliptic Curve Digital Signature Algorithm (ECDSA), 
    *                which provides strong security and performance.
    * - Returns: A tuple containing the private and public keys
    * - Throws: An error if the key pair cannot be generated
    */
   public static func getKeyPair() throws -> KeyPair {
      // Create a new private key.
      let privKey: PrivKey = .init()
      // Generate the raw data representation of the public key using the private key
      let pubKeyData: Data = privKey.publicKey.rawRepresentation
      // Create a new public key from the raw data representation
      let pubKey: PubKey = try .init(rawRepresentation: pubKeyData)
      // Return the key pair as a tuple
      return .init(priv: privKey, pub: pubKey)
   }
   /**
    * Generates a shared symmetric key using the Elliptic Curve Diffie-Hellman key agreement algorithm and the HKDF key derivation function.
    * - Abstract: This function is used in the "shared-key-scheme" encryption scheme
    * - Description: This function generates a shared symmetric key using the 
    *                Elliptic Curve Diffie-Hellman key agreement algorithm and 
    *                the HKDF key derivation function. The shared symmetric key 
    *                is used in symmetric encryption schemes for both encryption 
    *                and decryption. The key is derived from a shared secret that 
    *                is generated from a private key and a public key, and an 
    *                app-defined salt. The salt is used to prevent rainbow table 
    *                attacks, which are a type of brute force attack that uses 
    *                precomputed tables to crack cryptographic keys.
    * - Parameters:
    *   - privKey: The private key to use in the key agreement algorithm
    *   - pubKey: The public key to use in the key agreement algorithm
    *   - salt: An app-defined salt to use in the key derivation process. Use unique salts for unique cases to prevent rainbow table attacks.
    * - Returns: The shared symmetric key
    * - Throws: An error if the key agreement or key derivation process fails
    */
   public static func getSharedKey(privKey: PrivKey, pubKey: PubKey, salt: Data = Cipher.defaultSalt) throws -> SymmetricKey { // Local privey, External pubkey
      // Create a shared secret from the private and public keys using the Elliptic Curve Diffie-Hellman key agreement algorithm.
      let sharedSecret: SharedSecret = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
      // Derive a symmetric key from the shared secret using the HKDF key derivation function
      // - SHA256 is used as the hash function
      // - The specified salt is used to prevent rainbow table attacks
      // - No shared info is used
      // - The output byte count is set to 32 to generate a 256-bit key
      return sharedSecret.hkdfDerivedSymmetricKey(
         using: SHA256.self, // The hash function to use for key derivation
         salt: salt, // The salt to use for key derivation
         sharedInfo: Data(), // The shared info to use for key derivation
         outputByteCount: 32 // The number of bytes to output for the derived key
      )
   }
   /**
    * Generates a symmetric key from a given password using the SHA256 hash function
    * - Abstract: This function is used to add password-protected encryption 
    *             and decryption (e.g. encrypting raw data with a password).
    * - Description: This function generates a symmetric key from a given 
    *                password. The password is first converted into a Data 
    *                object, then hashed using the SHA256 function. The 
    *                resulting hash is then converted into a string, and the 
    *                first 32 bytes of this string are used to create the 
    *                symmetric key. This key can be used for symmetric 
    *                encryption and decryption operations.
    * - Remark: Make sure the password is sufficiently strong. Use word 
    *           combinations or long random strings instead of memorable 
    *           passwords. Strong passwords are less likely to be broken 
    *           with brute force attacks.
    * - Parameters:
    *   - password: The password used to generate the key
    * - Returns: The symmetric key
    * - Throws: An error if the key cannot be generated
    */
   public static func getPasswordKey(password: String, salt: Data = Cipher.defaultSalt) throws -> SymmetricKey {
      // Convert the password string to a Data object.
      guard let passwordData = password.data(using: .utf8) else {
         throw NSError(domain: "password data error", code: 0)
      }
      // Combine the password data with the salt.
      var combinedData = passwordData
      combinedData.append(salt)
      // Create a SHA256 hash from the combined data.
      let hash = SHA256.hash(data: combinedData)
      // Use the hash data directly to create a SymmetricKey.
      return SymmetricKey(data: hash)
      // Fixme: ⚠️️ conider using (check with copilot): 
      // try HKDF(password: password, salt: salt)
   }
   /**
    * Returns the raw data representation of a private key
    * - Description: This function retrieves the raw data representation of a 
    *                given private key. This raw data can be used for various 
    *                purposes such as securely storing the private key or 
    *                transmitting it over a network.
    * - Remark: This data can be used to store the private key in a secure 
    *           location, such as the keychain.
    * - Remark: The raw data can be converted back to a `PrivKey` using 
    *           `Cipher.getPrivKeyData(privKey: key)`.
    * - Parameter privKey: The private key to derive the data from
    */
   public static func getPrivKeyData(privKey: SymmetricKey) -> Data {
      privKey.withUnsafeBytes {
         Data(Array($0)) // Converts key to raw data
      }
   }
   /**
    * Derives a symmetric key from a given data object using the SHA256 hash function
    * - Description: This function takes a given data object and uses the SHA256 
    *                hash function to derive a symmetric key. This derived key 
    *                can then be used for symmetric encryption and decryption 
    *                operations.
    * - Remark: This function is used to generate a symmetric key from a seed 
    *           data object (e.g. a shared secret).
    * - Parameters:
    *   - data: The data used to derive the key
    * - Returns: The symmetric key
    * - Throws: An error if the key cannot be derived
    */
   public static func getPrivKey(data: Data) -> SymmetricKey {
      SymmetricKey(data: data)
   }
}
