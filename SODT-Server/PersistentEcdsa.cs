using System.Security.Cryptography;

namespace SODT_Server
{
	public static class PersistentEcdsa
	{
		private const string PublicCertPath = "certs/public/ecdsa_cert.pem"; 
		private const string PrivateCertPath = "certs/private/ecdsa_cert.pem";
		
		private static void EnsureCertDirectoriesExist()
		{
			string? publicDir = Path.GetDirectoryName(PublicCertPath);
			string? privateDir = Path.GetDirectoryName(PrivateCertPath);
			
			if (publicDir == null || privateDir == null)
				throw new InvalidOperationException("Invalid certificate paths.");
			
			if (!Directory.Exists(publicDir))
				Directory.CreateDirectory(publicDir);
			if (!Directory.Exists(privateDir))
				Directory.CreateDirectory(privateDir);
		}
		
		public static ECDsa GetOrCreateEcdsa()
		{
			if (File.Exists(PrivateCertPath) && File.Exists(PublicCertPath))
			{
				var ecdsa = ECDsa.Create();
				ecdsa.ImportFromPem(File.ReadAllText(PrivateCertPath));
				return ecdsa;
			}
			else
			{
				EnsureCertDirectoriesExist();
				var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
				File.WriteAllText(PrivateCertPath, ecdsa.ExportECPrivateKeyPem());
				File.WriteAllText(PublicCertPath, ecdsa.ExportSubjectPublicKeyInfoPem());
				return ecdsa;
			}
		}
		
		public static void ForceRegenerateEcdsa()
		{
			EnsureCertDirectoriesExist();
			var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
			File.WriteAllText(PrivateCertPath, ecdsa.ExportECPrivateKeyPem());
			File.WriteAllText(PublicCertPath, ecdsa.ExportSubjectPublicKeyInfoPem());
		}
	}
}