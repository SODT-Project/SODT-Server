using System.Security.Cryptography;

namespace SODT_Server
{
	public abstract class RsaEncryption : RSA
	{
		private const string PrivateKeyPath = "certs/private.key";
		private const string PublicKeyPath = "certs/public.key";

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
			RSA enc = RSA.Create(4096);
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
		public const int NonceSize = 12;
		public const int TagSize = 16;
		
		public static void EncryptAesGcm(AesGcm aes, IBaseMessage baseMessage, Span<byte> finalMessage)
		{
			Span<byte> nonce = finalMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize);
			Span<byte> tag = finalMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize);
			Span<byte> ciphertext = finalMessage[MessageHelper.HeaderSize..];
				
			// handle encryption
			RandomNumberGenerator.Fill(nonce);
			aes.Encrypt(nonce, baseMessage.ToBytes(), ciphertext, tag);
		}

		public static void DecryptAesGcm(AesGcm aes, ReadOnlySpan<byte> encryptedMessage, Span<byte> decryptedMessage)
		{
			aes.Decrypt(
				encryptedMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize),
				encryptedMessage[MessageHelper.HeaderSize..],
				encryptedMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize),
				decryptedMessage);
		}
	}
}