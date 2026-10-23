using System.Security.Cryptography;

namespace SODT_Common
{
	public static class EncryptionHandler
	{
		public static void EncryptAesGcm(AesGcm aes, IBaseMessage baseMessage, Span<byte> finalMessage)
		{
			if (finalMessage.Length != MessageHelper.FullMessageSize)
			{
				throw new InvalidOperationException("FinalMessage has wrong size. It should be " + MessageHelper.FullMessageSize + " bytes.");
			}
			// slice the final message into its components
			// because of Span<byte> the slices are just references to the original array. This eliminates memory allocations and copying.
			Span<byte> nonce = finalMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize); // nonce starts after the id
			Span<byte> tag =
				finalMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize); // tag starts after the id and nonce
			Span<byte>
				ciphertext = finalMessage[
					MessageHelper
							.HeaderSizeWithoutContentLengthSize
						..]; // ciphertext starts after the header (id + nonce + tag) and goes to the end of the message

			// handle encryption
			RandomNumberGenerator.Fill(nonce);

			// encrypt the base message and write the ciphertext and tag inside the final message
			aes.Encrypt(nonce, baseMessage.ToBytes(), ciphertext, tag);
		}

		public static void DecryptAesGcm(AesGcm aes, ReadOnlySpan<byte> encryptedMessage, Span<byte> decryptedMessage)
		{
			if (encryptedMessage.Length != MessageHelper.FullMessageSize)
			{
				throw new InvalidOperationException("EncryptedMessage has wrong size. It should be " + MessageHelper.FullMessageSize + " bytes.");
			}
			aes.Decrypt(
				encryptedMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize),
				encryptedMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..],
				encryptedMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize),
				decryptedMessage);
		}
		
		/// <summary>
		/// Generates an aes session key from the key exchange message with the other client. <br></br>
		/// Key generation uses ecdh and the session password hash if set.
		/// </summary>
		/// <param name="ownPublicKey"></param>
		/// <param name="remotePublicKey"></param>
		/// <param name="privateSessionPasswordHash"></param>
		/// <returns></returns>
		/// 
		public static AesGcm GenerateSessionKey(ECDiffieHellman ownPublicKey, byte[] remotePublicKey, byte[]? privateSessionPasswordHash = null)
		{
			//create shared secret
			var otherPublicKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			otherPublicKey.ImportSubjectPublicKeyInfo(remotePublicKey, out _);
			//do not use sharedSecret directly as key. Use a key derivation function to derive a key from the shared secret.
			byte[] derivedKey = ownPublicKey.DeriveKeyFromHash(otherPublicKey.PublicKey, HashAlgorithmName.SHA256);
			//create aes
			AesGcm aes;
			if (privateSessionPasswordHash == null)
				aes = new AesGcm(derivedKey, MessageHelper.TagSize);
			else //if a session passwort is set for client authentication, use it as key
				using (HMACSHA256 hmac = new(privateSessionPasswordHash))
					aes = new AesGcm(hmac.ComputeHash(derivedKey), MessageHelper.TagSize);
			return aes;
		}
		
		/// <summary>
		/// Compares the session password hash of the client with own public session password hash.
		/// </summary>
		/// <param name="ownPublicSessionPasswordHash"> The public session password hash of the current client.</param>
		/// <param name="remotePublicSessionPasswordHash"> The public session password hash of the other client.</param>
		/// <returns> <see langword="true"/> if the session password hash matches, otherwise <see langword="false"/>.</returns>
		public static bool DoesSessionHashMatch(byte[]? ownPublicSessionPasswordHash, byte[]? remotePublicSessionPasswordHash) // TODO return StatusCode?
		{
			// both session password hashes are null, no session password is set for authentication
			if (ownPublicSessionPasswordHash == null && remotePublicSessionPasswordHash == null)
				return true;
			
			//exactly one of the session password hashes is null
			if ((ownPublicSessionPasswordHash == null) ^ (remotePublicSessionPasswordHash == null))
				return false;
			
			return ownPublicSessionPasswordHash.SequenceEqual(remotePublicSessionPasswordHash);
		}
	}
}