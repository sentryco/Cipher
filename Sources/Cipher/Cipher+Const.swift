import Foundation
import CryptoKit
import Logger
/**
 * Const
 */
extension Cipher {
   /**
    * Generates a private symmetric key of size 256 bits for local security.
    * - Description: This property generates a private symmetric key of size 
    *                256 bits. The key is used for local security purposes 
    *                such as encrypting and decrypting data. It is generated 
    *                using the CryptoKit framework's SymmetricKey class, which 
    *                provides a secure and efficient way to generate symmetric 
    *                keys.
    * - Note: The symmetric key doesn't have a public key, only a private key.
    * - Note: The privKey256 function generates a private symmetric key of size 
    *         256 bits for local security purposes.
    * - Fixme: ⚠️️ Consider generating the `SymmetricKey` in an enclave for better entropy. Further research is needed.
    */
   public static var privKey256: SymmetricKey {
      SymmetricKey(size: .bits256) // Make private symmetric key
   }
   /**
    * Returns the private key data for the Curve25519 key agreement.
    * - Description: This property returns the raw data representation of the 
    *                private symmetric key generated for Curve25519 key 
    *                agreement. This is useful when the key needs to be stored 
    *                or transmitted in a raw format.
    */
   public static var privKeyData: Data {
      getPrivKeyData(privKey: privKey256)
   }
}
/**
 * Salt
 * - Abstract: This section contains constants and static variables related to 
 *             the Cipher class, including cryptographic keys and salts.
 * - Description: This section contains constants and static variables related 
 *                to the Cipher class, including cryptographic keys and salts. 
 *                These constants are used to ensure secure encryption and 
 *                decryption processes within the application.
 * - Fixme: ⚠️️ move to +Salt file ?
 * - Fixme: ⚠️️ chat with gpt about salt, learn more, edge cases, gotchas etc
 * - Note: Some best practices for using salt in password hashing are:
 * - 1. Use a unique salt for each password hash to prevent attackers from 
 *      using precomputed hashes (rainbow tables) for attacks.
 * - 2. Store the salt along with the hashed password, as the same salt must 
 *      be used when verifying the password.
 * - 3. Use a random salt of sufficient length (at least 64 bits) to ensure 
 *      that each salt is unique and unpredictable.
 * - 4. Consider using a cryptographically secure random number generator to 
 *      generate the salt.
 * - 5. Avoid using predictable or static values for the salt, such as the 
 *      user's username or email address.
 * - 6. Consider using a pepper (a secret key) in addition to the salt to 
 *      further increase the security of the password hash.
 * - 7. Regularly review and update the salt and hashing algorithms to ensure 
 *      that they are up-to-date with the latest security best practices.
 */
extension Cipher {
   /**
    * This is the default salt (Use unique salts for different use-cases)
    * - Abstract: This is the default salt used for password hashing.
    * - Description: This is the default salt used for password hashing. It is a 
    *                fixed value that is combined with the password before the 
    *                hashing process. The use of a salt prevents attackers from 
    *                using precomputed tables (rainbow tables) to crack the 
    *                password. It is important to note that the salt value must 
    *                be unique for each user and must be stored in a secure 
    *                manner.
    * - Remark: Salt has to be the same when you encrypt and decrypt. So it has 
    *           to be stored. and cant be generated on the fly
    * - Remark: Having a salt added to the password reduces the ability to use 
    *           precomputed hashes (rainbow tables) for attacks, and means that 
    *           multiple passwords have to be tested individually, not all at 
    *           once.
    * - Remark: The standard recommends a salt length of at least 64 bits. (But 
    *           might be connected with length of hash)
    * - Remark: Use the `randomSalt` method to generate salt const for different 
    *           use cases etc
    * - Fixme: ⚠️️ Do more research security regarding salt etc, best practices 
    *          etc, opensource the salt part maybe?
    * - Fixme: ⚠️️ Remove the forced fatal error at some point 👈
    * - Note: more on salt: https://en.wikipedia.org/wiki/Salt_(cryptography)#:~:
    *         text=In%20cryptography%2C%20a%20salt%20is,to%20safeguard%20passwords
    *         %20in%20storage.
    */
   public static var defaultSalt: Data = {
      // This is the default salt used for password hashing
      let salt128Bit: String = """
      0+RKhXLTOEFxRs3MpHaNmzxs5ZjxcJQLMJ24Ims1ThGy74y/Lsd1BB4Eb2/UOkHqBBIVQlxCBuaqJUe8vOVtETIB/BG2nbd6Qb6sFTX/g4g26DM6/2KfXAG1BA5d9nAiNj1OQVFK+L/rzynuz0wvGLGjkbWZkvnMG/SAoh7m/lE=
      """
      // Convert the salt string to a Data object.
      guard let saltData: Data = .init(base64Encoded: salt128Bit) else {
         // Log an error and terminate the program if the salt cannot be decoded.
         Logger.error("\(Trace.trace())", tag: .security)
         fatalError("Error, defaultSalt")
      }
      // Return the salt data.
      return saltData
   }()
}
/**
 * - Fixme: ⚠️️⚠️️ Test with random salt, aledgedly we should not use hardcoded salt: https://www.andyibanez.com/posts/common-cryptographic-operations-with-cryptokit/
 */
extension Cipher {
   /**
    * From entropy
    * - Abstract: Generates a random salt of the specified length using 
    *             cryptographically secure random numbers.
    * - Description: This method generates a random salt of the specified length 
    *                using cryptographically secure random numbers. The salt is 
    *                used to enhance security in cryptographic processes by 
    *                adding an additional layer of randomness. It is particularly 
    *                useful in password hashing where it prevents the use of 
    *                precomputed tables (rainbow tables) for cracking passwords.
    * - Remark: Ideally, the length of Salt should be as long as the output of 
    *           the hash. For example, if the hash output is 32 bytes, the salt 
    *           length should be at least 32 bytes, if not more. This step is an 
    *           addition to passwords with specialized characters.
    * - Fixme: ⚠️️ Figure out how to calc the hash lenght
    * - Fixme: ⚠️️ Figure out how to remove the forced unwrap? 👈 make it optional?
    * ## Examples:
    * let salt = Cipher.randomSalt(length: 128)
    * let saltStr = salt.Cipher.defaultSalt.base64EncodedString()
    * let saltData: Data = .init(base64Encoded: saltStr)!
    * - Parameter length: Needed length
    */
   public static func randomSalt(length: Int) -> Data {
      // Create a new Data object with the specified length.
      var data: Data = .init(count: length)
      // Generate cryptographically secure random bytes and store them in the Data object.
      let result = data.withUnsafeMutableBytes {
         SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
      }
      // Check if the random byte generation was successful.
      guard result == errSecSuccess else {
         // Log an error and terminate the program if the salt cannot be generated.
         Logger.error("Failed to generate random salt", tag: .security)
         fatalError("Error generating random salt")
      }
      // Return the Data object containing the random bytes.
      return data
   }
   /**
    * From 256bit encryption (Not in use yet)
    * - Description: This method generates a random salt for cryptographic 
    *                operations using a 256-bit symmetric key. The generated 
    *                salt is then converted into a Data object for easier 
    *                storage and transmission.
    * - Fixme: ⚠️️ There is SymmetricKey(size: .bitCount(...)) that we might use 👈 figure out how to calc ideal multplier
    */
   public static func randomSalt() -> Data {
      // Generate a new symmetric key of size 256 bits.
      let symKeySalt: SymmetricKey = .init(size: .bits256)
      // Convert the symmetric key to a Data object.
      // Note: This is done to make it easier to store and transmit the key.
      return symKeySalt.withUnsafeBytes { Data($0) }
   }
}
