using System.Security.Cryptography;

namespace SODT_Server
{
	public abstract class RSAEncryption : RSA
	{
		private const string privateKeyPath = "certs/private.key";
		private const string publicKeyPath = "certs/public.key";

		/// <summary>
		/// Loads server's RSA key pair from files or generates new ones if they don't exist.
		/// </summary>
		public static new RSA Create()
		{
			GenerateKeys();
			RSA enc = RSA.Create();
			enc.ImportFromPem(File.ReadAllText(privateKeyPath));
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
			if (forceRegeneration || !File.Exists(privateKeyPath) || !File.Exists(publicKeyPath))
			{
				File.WriteAllText(privateKeyPath, enc.ExportRSAPrivateKeyPem());

				// Write the public key to a file in PEM format
				File.WriteAllText(publicKeyPath, enc.ExportRSAPublicKeyPem());
			}
		}

	}
}