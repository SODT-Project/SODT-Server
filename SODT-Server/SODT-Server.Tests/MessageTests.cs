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
		public void MessagePolyMorphismTest()
		{
			var clientList = ClientList.CreateRequest();
			IBaseMessage genericMessage = clientList;
			Assert.Equal(genericMessage.ToJson(), clientList.ToJson());
		}
	}
}