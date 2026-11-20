using System.Security.Cryptography;

namespace SODT_Server.SODT_Common
{
	/// <summary>
	/// Class that contains a collection of methods to handle encryption and decryption of messages using AES-GCM and ECDH key exchange.
	/// This class is identical for the client cli and the server.
	/// </summary>
	public static class EncryptionHandler
	{
		/// <summary>
		/// Encrypts a base message using AES-GCM and writes the resulting ciphertext, nonce, and tag into the final message span at the appropriate positions. <br></br>
		/// </summary>
		/// <param name="aes">The AES-GCM instance to use for encryption.</param>
		/// <param name="baseMessage">The base message to encrypt.</param>
		/// <param name="finalMessage">The final message span reference to write the encrypted data into.</param>
		/// <exception cref="InvalidOperationException">Thrown when the final message span has the wrong size.</exception>
		public static void EncryptAesGcm(AesGcm aes, IBaseMessage baseMessage, Span<byte> finalMessage)
		{
			if (finalMessage.Length != MessageHelper.FullMessageSize)
			{
				throw new InvalidOperationException("FinalMessage has wrong size. It should be " + MessageHelper.FullMessageSize + " bytes.");
			}
			
			// slice the final message into its components
			// nonce starts after the id
			Span<byte> nonce = finalMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize); 
			// tag starts after the id and nonce
			Span<byte> tag = finalMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize); 
			// ciphertext starts after the header (id + nonce + tag) and goes to the end of the message
			Span<byte> ciphertext = finalMessage[ MessageHelper.HeaderSizeWithoutContentLengthSize ..]; 

			// handle encryption
			RandomNumberGenerator.Fill(nonce); // generate a random nonce for each message
			// encrypt the base message and write the ciphertext and tag inside the final message
			aes.Encrypt(nonce, baseMessage.ToBytes(), ciphertext, tag);
		}

		/// <summary>
		/// Decrypts an encrypted message using AES-GCM and writes the resulting plaintext into the decrypted message span. <br></br>
		/// </summary>
		/// <param name="aes">The AES-GCM instance to use for decryption.</param>
		/// <param name="encryptedMessage">The encrypted message to decrypt. The message must have the size of a full message.</param>
		/// <param name="decryptedMessage">The span to write the decrypted message into. The span must have the size of 4066 bytes.</param>
		/// <exception cref="InvalidOperationException">Thrown when the encrypted message or the decrypted message has the wrong size.</exception>
		public static void DecryptAesGcm(AesGcm aes, ReadOnlySpan<byte> encryptedMessage, Span<byte> decryptedMessage)
		{
			if (encryptedMessage.Length != MessageHelper.FullMessageSize)
				throw new InvalidOperationException("EncryptedMessage has wrong size. It should be " + MessageHelper.FullMessageSize + " bytes.");
			
			if (decryptedMessage.Length != MessageHelper.MessageWithContentSize)
				throw new InvalidOperationException("DecryptedMessage has wrong size. It should be " + MessageHelper.MessageWithContentSize + " bytes.");
			
			aes.Decrypt(
				encryptedMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize),
				encryptedMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..],
				encryptedMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize),
				decryptedMessage);
		}
		
		/// <summary>
		/// Generates an AES session key from the key exchange message with the other client. <br></br>
		/// Key generation uses ECDH and a key derivation function to derive a key from the shared secret. <br></br>
		/// </summary>
		/// <param name="ownPublicKey">The public key of the current client for this session and this key exchange.</param>
		/// <param name="remotePublicKey">The public key of the other client for this session and this key exchange.</param>
		/// <returns>An AES-GCM instance initialized with the generated session key.</returns>
		public static AesGcm GenerateSessionKey(ECDiffieHellman ownPublicKey, byte[] remotePublicKey)
		{
			//create shared secret
			var otherPublicKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			otherPublicKey.ImportSubjectPublicKeyInfo(remotePublicKey, out _);
			//do not use sharedSecret directly as key. Use a key derivation function to derive a key from the shared secret.
			byte[] derivedKey = ownPublicKey.DeriveKeyFromHash(otherPublicKey.PublicKey, HashAlgorithmName.SHA256);
			//create aes
			return new AesGcm(derivedKey, MessageHelper.TagSize);
		}
		
		/// <summary>
		/// Generates a shared phrase from the key exchange message with the other client. <br></br>
		/// The shared phrase is generated from the derived key using ECDH and a key.
		/// The shared phrase can be used for verification of the key exchange and to ensure that both clients have the same derived key. <br></br>
		/// </summary>
		/// <param name="ownPublicKey">The public key of the current client for this session and this key exchange.</param>
		/// <param name="remotePublicKey">The public key of the other client for this session and this key exchange.</param>
		/// <returns>A string representing the shared phrase in the hex format "XX-XX-XX-XX-XX".</returns>
		public static string GetSharedPhrase(ECDiffieHellman ownPublicKey, byte[] remotePublicKey)
		{
			var otherPublicKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			otherPublicKey.ImportSubjectPublicKeyInfo(remotePublicKey, out _);
			byte[] derivedKey = ownPublicKey.DeriveKeyFromHash(otherPublicKey.PublicKey, HashAlgorithmName.SHA256);
			return $"{derivedKey[0]:X2}-{derivedKey[4]:X2}-{derivedKey[8]:X2}-{derivedKey[16]:X2}-{derivedKey[31]:X2}";
		}
	}
}