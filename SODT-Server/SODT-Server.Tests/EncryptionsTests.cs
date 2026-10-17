using System.Security.Cryptography;
using SODT_Common;

namespace SODT_Server.Tests
{
	public class EncryptionsTests
	{
		[Fact]
		public void EncryptAndDecryptLocalTests()
		{
			var testMessage = ClientList.CreateRequest();
			var key = RandomNumberGenerator.GetBytes(32);
			AesGcm aes = new AesGcm(key, MessageHelper.TagSize);
			Span<byte> enc = new byte[MessageHelper.FullMessageSize];
			Span<byte> dec = new byte[MessageHelper.MessageWithContentSize]; // decrypted message will be smaller than the encrypted message because the encrypted message contains the nonce and tag as well
			EncryptionHandler.EncryptAesGcm(aes, testMessage, enc);
			EncryptionHandler.DecryptAesGcm(aes, enc, dec);
			var resultMessage = MessageHandler.ParseDecryptedMessage(dec.ToArray());
			Assert.Equal(testMessage, resultMessage);

		}

		/*[Fact]
		public void DecryptDeiscoveryTest()
		{
			var tmpkey = RandomNumberGenerator.GetBytes(32);
			RSA rsa = RsaEncryption.Create();
			var discovery = Discovery.CreateRequest(tmpkey);
			var decBytes = rsa.Decrypt(discovery.ToEncryptedBytes(rsa)[0..512], RSAEncryptionPadding.OaepSHA384);
			var decDiscorvery = (Discovery)MessageHandler.ParseDecryptedMessage(decBytes)!;
			Assert.Equal(discovery.ToJson(), decDiscorvery.ToJson()); // use string for easy compare
		}*/
	}
}