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

		[Fact]
		public void GenerateSessionKey_WithPasswordHash_DerivesMatchingKeys()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			byte[] passwordHash = SHA256.HashData("shared password"u8);
			using AesGcm ownSessionKey = EncryptionHandler.GenerateSessionKey(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo(),
				passwordHash);
			using AesGcm remoteSessionKey = EncryptionHandler.GenerateSessionKey(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo(),
				passwordHash);
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			IBaseMessage message = PingPong.CreateRequest();

			EncryptionHandler.EncryptAesGcm(ownSessionKey, message, encryptedMessage);
			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			EncryptionHandler.DecryptAesGcm(remoteSessionKey, encryptedMessage, decryptedMessage);

			Assert.Equal(message.ToBytes(), decryptedMessage);
		}

		[Fact]
		public void GenerateSessionKey_WithDifferentPasswordHash_CannotDecrypt()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using AesGcm ownSessionKey = EncryptionHandler.GenerateSessionKey(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo(),
				SHA256.HashData("password one"u8));
			using AesGcm remoteSessionKey = EncryptionHandler.GenerateSessionKey(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo(),
				SHA256.HashData("password two"u8));
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			EncryptionHandler.EncryptAesGcm(ownSessionKey, PingPong.CreateRequest(), encryptedMessage);

			Assert.ThrowsAny<CryptographicException>(() =>
				EncryptionHandler.DecryptAesGcm(
					remoteSessionKey,
					encryptedMessage,
					new byte[MessageHelper.MessageWithContentSize]));
		}

		[Theory]
		[InlineData(true, false, true)]
		[InlineData(false, false, false)]
		[InlineData(false, true, true)]
		public void DoesSessionHashMatch_ComparesHashesCorrectly(
			bool hashesAreEqual,
			bool useNullHashes,
			bool expectedResult)
		{
			byte[]? ownHash = useNullHashes ? null : [1, 2, 3];
			byte[]? remoteHash = useNullHashes
				? null
				: hashesAreEqual ? [1, 2, 3] : [1, 2, 4];

			Assert.Equal(expectedResult, EncryptionHandler.DoesSessionHashMatch(ownHash, remoteHash));
		}

		[Fact]
		public void DoesSessionHashMatch_WithOnlyOneNullHash_ReturnsFalse()
		{
			Assert.False(EncryptionHandler.DoesSessionHashMatch(null, [1, 2, 3]));
			Assert.False(EncryptionHandler.DoesSessionHashMatch([1, 2, 3], null));
		}

		[Fact]
		public void DoesSessionHashMatch_WithDifferentLengthHashes_ReturnsFalse()
		{
			Assert.False(EncryptionHandler.DoesSessionHashMatch([1, 2], [1, 2, 0]));
		}

	}
}
