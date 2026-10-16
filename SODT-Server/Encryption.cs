using System.Security.Cryptography;
using SODT_Common;

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
}