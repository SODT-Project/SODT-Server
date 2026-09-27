using System.Security.Cryptography;

namespace SODT_Server
{
	public abstract class RsaEncryption : RSA
	{
		private const string PrivateKeyPath = "certs/private.key";
		private const string PublicKeyPath = "certs/public.key";

		private const int RsaKeySizeBits = 4096;

		/// <summary>
		/// Loads server's RSA key pair from files or generates new ones if they don't exist.
		/// </summary>
		public static new RSA Create()
		{
			GenerateKeys();
			RSA enc = RSA.Create();
			enc.ImportFromPem(File.ReadAllText(PrivateKeyPath));
			return enc;
		}
		/// <summary>
		/// Generates RSA key pair and saves them to files if they don't exist.
		/// </summary>
		public static void GenerateKeys(bool forceRegeneration = false)
		{
			RSA enc = RSA.Create(RsaKeySizeBits);
			// Create the 'certs' directory if it doesn't already exist
			if (!Directory.Exists("certs"))
			{
				Directory.CreateDirectory("certs");
			}

			// Check if the private key and public key files exist, and generate new ones if they don't
			if (forceRegeneration || !File.Exists(PrivateKeyPath) || !File.Exists(PublicKeyPath))
			{
				File.WriteAllText(PrivateKeyPath, enc.ExportRSAPrivateKeyPem());

				// Write the public key to a file in PEM format
				File.WriteAllText(PublicKeyPath, enc.ExportRSAPublicKeyPem());
			}
		}
	}

	public static class EncryptionHandler
	{
		public static void EncryptAesGcm(AesGcm aes, IBaseMessage baseMessage, Span<byte> finalMessage)
		{
			// slice the final message into its components
			// because of Span<byte> the slices are just references to the original array. This eliminates memory allocations and copying.
			Span<byte> nonce = finalMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize); // nonce starts after the id
			Span<byte> tag = finalMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize); // tag starts after the id and nonce
			Span<byte> ciphertext = finalMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..]; // ciphertext starts after the header (id + nonce + tag) and goes to the end of the message
				
			// handle encryption
			RandomNumberGenerator.Fill(nonce);
			
			// encrypt the base message and write the ciphertext and tag inside the final message
			aes.Encrypt(nonce, baseMessage.ToBytes(), ciphertext, tag);
		}

		public static void DecryptAesGcm(AesGcm aes, ReadOnlySpan<byte> encryptedMessage, Span<byte> decryptedMessage)
		{
			aes.Decrypt(
				encryptedMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize),
				encryptedMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..],
				encryptedMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize),
				decryptedMessage);
		}
	}
}