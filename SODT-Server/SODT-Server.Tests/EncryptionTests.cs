using System.Security.Cryptography;
using SODT_Server.SODT_Common;

namespace SODT_Server.Tests
{
	public class EncryptionTests
	{
		[Fact]
		public void EncryptAesGcm_AndDecryptAesGcm_RoundTripMessage()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);
			IBaseMessage message = PingPong.CreateRequest();
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			encryptedMessage[0] = 7;
			encryptedMessage[1] = 9;

			EncryptionHandler.EncryptAesGcm(aes, message, encryptedMessage);

			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			EncryptionHandler.DecryptAesGcm(aes, encryptedMessage, decryptedMessage);

			Assert.Equal(message.ToBytes(), decryptedMessage);
			Assert.Equal([7, 9], encryptedMessage[..MessageHelper.IdSize]);
			Assert.NotEqual(
				message.ToBytes(),
				encryptedMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..]);
		}

		[Fact]
		public void EncryptAesGcm_WithWrongMessageSize_Throws()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);

			InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
				EncryptionHandler.EncryptAesGcm(
					aes,
					PingPong.CreateRequest(),
					new byte[MessageHelper.FullMessageSize - 1]));

			Assert.Contains("FinalMessage has wrong size", exception.Message);
		}

		[Fact]
		public void DecryptAesGcm_WithWrongMessageSize_Throws()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);

			InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
				EncryptionHandler.DecryptAesGcm(
					aes,
					new byte[MessageHelper.FullMessageSize - 1],
					new byte[MessageHelper.MessageWithContentSize]));

			Assert.Contains("EncryptedMessage has wrong size", exception.Message);
		}

		[Fact]
		public void DecryptAesGcm_WithTamperedCiphertext_Throws()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			EncryptionHandler.EncryptAesGcm(aes, PingPong.CreateRequest(), encryptedMessage);
			encryptedMessage[^1] ^= 1;

			Assert.ThrowsAny<CryptographicException>(() =>
				EncryptionHandler.DecryptAesGcm(
					aes,
					encryptedMessage,
					new byte[MessageHelper.MessageWithContentSize]));
		}

		[Fact]
		public void GenerateSessionKey_DerivesMatchingKeys()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using AesGcm ownSessionKey = EncryptionHandler.GenerateSessionKey(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo());
			using AesGcm remoteSessionKey = EncryptionHandler.GenerateSessionKey(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo());
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			IBaseMessage message = PingPong.CreateResponse();

			EncryptionHandler.EncryptAesGcm(ownSessionKey, message, encryptedMessage);
			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			EncryptionHandler.DecryptAesGcm(remoteSessionKey, encryptedMessage, decryptedMessage);

			Assert.Equal(message.ToBytes(), decryptedMessage);
		}
	}
}
