import Foundation
import CryptoKit
/**
 * High-level `CryptoKit` wrapper
 * - Description: Cipher is a high-level wrapper for the CryptoKit framework, 
 *                providing a simplified interface for cryptographic operations. 
 *                It uses the ChaChaPoly algorithm for encryption and decryption, 
 *                and the Diffie-Hellman key agreement to create private/public 
 *                key pairs. Additionally, it employs the HKDF method for shared 
 *                key creation.
 * - Remark: Cipher uses `ChaChaPoly` to encrypt / decrypt payloads
 * - Remark: `Diffie-Hellmann` key agreement is used to create a private / public 
 *           key pair
 * - Remark: And we use HKDF https://en.wikipedia.org/wiki/HKDF to create a shared 
 *           key
 * - Note: Nice overview of CryptoKit: 
 *         https://medium.com/swlh/cryptokit-tutorial-how-to-use-cryptokit-on-ios13-apps-5961019752f5
 */
public final class Cipher {}
