import Foundation
import CryptoKit
/**
 * Alias for the private key used in Curve25519 key agreement.
 * - Abstract: This is a convenient shortcut to make the code more readable.
 * - Description: This typealias represents the private key used in Curve25519 
 *                key agreement protocol. It simplifies the code by providing 
 *                a more readable name for the private key type.
 */
public typealias PrivKey = Curve25519.KeyAgreement.PrivateKey
/**
 * Alias for the public key used in Curve25519 key agreement.
 * - Abstract: This is a convenient shortcut to make the code more readable.
 * - Description: This typealias represents the public key used in Curve25519 
 *                key agreement protocol. It simplifies the code by providing 
 *                a more readable name for the public key type.
 */
public typealias PubKey = Curve25519.KeyAgreement.PublicKey
/**
 * A key pair consisting of a private key and a public key.
 * - Abstract: This is a convenient shortcut to make the code more readable.
 * - Description: This typealias represents a key pair used in Curve25519 key 
 *                agreement protocol. It includes a private key and a public 
 *                key, which are essential for cryptographic operations such 
 *                as encryption and decryption.
 * - fixme: ⚠️️ Consider creating a struct instead of typealias for better readability and maintainability.
 */
 public struct KeyPair {
    // The private key of the key pair
    public let priv: PrivKey
    // The public key of the key pair
    public let pub: PubKey
    public init(priv: PrivKey, pub: PubKey) {
       self.priv = priv
       self.pub = pub
    }
}
// public typealias KeyPair = (
//     priv: PrivKey, 
//     pub: PubKey 
// )
