namespace SODT_Server.Tests
{
	public class MessageTests
	{
		[Fact]
		public void MessageToByteConversionSizeTest()
		{
			var testMessage = ClientList.CreateRequest();
			var bytes = testMessage.ToBytes();
			Assert.Equal(MessageHelper.MessageContentSize + MessageHelper.ContentLengthSize, bytes.Length);
		}
		[Fact]
		public void MessageTypeCheck()
		{
			var clientList = ClientList.CreateRequest();
			IBaseMessage genericMessage = clientList;
			// TODO
		}
	}
}