using System.Text;
using System.Text.Json;
using SODT_Server.SODT_Common;

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
		
		public static IEnumerable<object[]> Messages =>
		[
			[Discovery.CreateRequest([1, 2, 3])],
			[Discovery.CreateResponse(7, [4, 5, 6], [7, 8, 9])],
			[PingPong.CreateRequest()],
			[PingPong.CreateResponse()],
			[KeyExchange.CreateRequest([1, 2])],
			[KeyExchange.CreateResponse([1, 2])],
			[KeyExchange.CreateError(KeyExchange.CreateRequest([1, 2]))],
			[KeyExchange.CreateDenied(KeyExchange.CreateRequest([1, 2]))],
			[Disconnect.CreateRequest()],
			[ClientList.CreateRequest()],
			[ClientList.CreateResponse([1, 2, 3])],
			[Transfer.CreateRequest("file.txt", 123, [1, 2, 3])],
			[Transfer.CreateResponse(Transfer.CreateRequest("file.txt", 123, [1, 2, 3]))],
			[Transfer.CreateAcknowledgement(Transfer.CreateRequest("file.txt", 123, [1, 2, 3]))],
			[Transfer.CreateError(Transfer.CreateRequest("file.txt", 123, [1, 2, 3]))],
			[Transfer.CreateDenied(Transfer.CreateRequest("file.txt", 123, [1, 2, 3]))],
			[TransferData.CreateRequest(42, new byte[] { 1, 2, 3 }, 10)]
		];

		[Fact]
		public void BaseMessage_ConvertsToJsonAndFixedSizePacket()
		{
			IBaseMessage message = new BaseMessage
			{
				Uuid = 1,
				Code = (int)PacketCode.Request,
				Type = "base"
			};

			using JsonDocument json = JsonDocument.Parse(message.ToJson());
			byte[] bytes = message.ToBytes();

			Assert.Equal(JsonValueKind.Object, json.RootElement.ValueKind);
			Assert.Equal(MessageHelper.MessageWithContentSize, bytes.Length);
			Assert.Equal(message.ToJson(), Encoding.UTF8.GetString(bytes, MessageHelper.ContentLengthSize,
				BitConverter.ToUInt16(bytes)));
		}

		[Theory]
		[MemberData(nameof(Messages))]
		public void MessageConversions_ProduceValidFixedSizePackets(IBaseMessage message)
		{
			using JsonDocument json = JsonDocument.Parse(message.ToJson());
			byte[] bytes = message.ToBytes();

			Assert.Equal(JsonValueKind.Object, json.RootElement.ValueKind);
			Assert.Equal(MessageHelper.MessageWithContentSize, bytes.Length);
			Assert.Equal(Encoding.UTF8.GetByteCount(message.ToJson()), BitConverter.ToUInt16(bytes));
			Assert.All(
				bytes[(MessageHelper.ContentLengthSize + BitConverter.ToUInt16(bytes))..],
				byteValue => Assert.Equal(0, byteValue));
			Assert.Equal(MessageHelper.ToBytes(message), bytes);
		}

		[Theory]
		[MemberData(nameof(Messages))]
		public void MessageHandler_ParsesEveryMessageType(IBaseMessage message)
		{
			IBaseMessage? parsed = MessageHandler.ParseDecryptedMessage(message.ToBytes());

			Assert.NotNull(parsed);
			Assert.IsType(message.GetType(), parsed);
			Assert.Equal(message.ToJson(), parsed!.ToJson());
			Assert.Equal(message.Type, parsed.Type);
			Assert.Equal(message.Code, parsed.Code);
			Assert.Equal(message.Uuid, parsed.Uuid);
		}

		[Fact]
		public void KeyExchangeStatusFactories_PreserveMessageDataAndUuid()
		{
			KeyExchange request = KeyExchange.CreateRequest([1, 2]);

			KeyExchange error = KeyExchange.CreateError(request);
			KeyExchange denied = KeyExchange.CreateDenied(request);

			Assert.Equal(request.Uuid, error.Uuid);
			Assert.Equal(request.Uuid, denied.Uuid);
			Assert.Equal((int)PacketCode.Error, error.Code);
			Assert.Equal((int)PacketCode.Denied, denied.Code);
			Assert.Equal(request.Key, error.Key);
		}

		[Fact]
		public void TransferStatusFactories_PreserveMessageDataAndUuid()
		{
			Transfer request = Transfer.CreateRequest("file.txt", 123, [1, 2, 3]);

			Transfer response = Transfer.CreateResponse(request);
			Transfer acknowledgement = Transfer.CreateAcknowledgement(request);
			Transfer error = Transfer.CreateError(request);
			Transfer denied = Transfer.CreateDenied(request);

			Assert.Equal(request.Uuid, response.Uuid);
			Assert.Equal(request.Uuid, acknowledgement.Uuid);
			Assert.Equal(request.Uuid, error.Uuid);
			Assert.Equal(request.Uuid, denied.Uuid);
			Assert.Equal((int)PacketCode.Ok, response.Code);
			Assert.Equal((int)PacketCode.Ack, acknowledgement.Code);
			Assert.Equal((int)PacketCode.Error, error.Code);
			Assert.Equal((int)PacketCode.Denied, denied.Code);
			Assert.Equal(request.FileName, denied.FileName);
			Assert.Equal(request.FileSize, denied.FileSize);
			Assert.Equal(request.FileHash, denied.FileHash);
		}

		[Fact]
		public void MessageHelper_ToBytes_WithOversizedMessage_Throws()
		{
			IBaseMessage message = new OversizedMessage();

			ArgumentException exception = Assert.Throws<ArgumentException>(() => MessageHelper.ToBytes(message));

			Assert.Contains("Message size is too large", exception.Message);
		}

		[Theory]
		[InlineData("")]
		[InlineData("{\"type\":\"unknown\"}")]
		[InlineData("{\"type\":\"pingpong\"")]
		public void MessageHandler_WithInvalidMessage_ReturnsNull(string json)
		{
			byte[] content = Encoding.UTF8.GetBytes(json);
			byte[] packet = new byte[MessageHelper.MessageWithContentSize];
			Array.Copy(BitConverter.GetBytes((ushort)content.Length), packet, MessageHelper.ContentLengthSize);
			Array.Copy(content, 0, packet, MessageHelper.ContentLengthSize, content.Length);

			Assert.Null(MessageHandler.ParseDecryptedMessage(packet));
		}

		[Fact]
		public void MessageHandler_WithPacketTooShort_ReturnsNull()
		{
			Assert.Null(MessageHandler.ParseDecryptedMessage([1]));
		}

		private sealed class OversizedMessage : IBaseMessage
		{
			public int Uuid { get; init; } = 1;
			public int Code { get; init; } = (int)PacketCode.Request;
			public string Type { get; init; } = "oversized";

			public string ToJson() => $"{{\"type\":\"{new string('x', MessageHelper.MessageContentSize)}\"}}";
			public byte[] ToBytes() => MessageHelper.ToBytes(this);
		}
	}
}