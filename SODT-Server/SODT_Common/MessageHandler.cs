using System.Text;
using System.Text.Json;

namespace SODT_Common
{
	/// <summary>
	/// Represents a message handler class that can parse and send messages over a network stream.
	/// </summary>
	public static class MessageHandler
	{

		/// <summary>
		/// Parses a message packet received from a client into a <see cref="IBaseMessage"/> object.
		/// </summary>
		/// <param name="messageWithContentSize"> Decrypted message packet received from the client.</param>
		/// <returns> The parsed <see cref="IBaseMessage"/> message object or <see langword="null"/> if parsing fails.</returns>
		public static IBaseMessage? ParseDecryptedMessage(ReadOnlySpan<byte> messageWithContentSize)
		{
			try
			{
				// get first two bytes as length of content
				ushort length = BitConverter.ToUInt16(messageWithContentSize[..MessageHelper.ContentLengthSize]);
				
				// get the content after the length bytes and pass it to HandleType for deserialization
				return HandleType(messageWithContentSize[MessageHelper.ContentLengthSize..(length + MessageHelper.ContentLengthSize)]);
			}
			catch (Exception ex)
			{
				// Handle any JSON formatting errors that occur during deserialization.
				return null;
			}
		}

		private static IBaseMessage HandleType(ReadOnlySpan<byte> content)
		{
			return JsonSerializer.Deserialize<BaseMessage>(content).Type switch
			{
				"discovery" => JsonSerializer.Deserialize<Discovery>(content),
				"pingpong" => JsonSerializer.Deserialize<PingPong>(content),
				"clients" => JsonSerializer.Deserialize<ClientList>(content),
				"exchange" => JsonSerializer.Deserialize<KeyExchange>(content),
				"transfer" => JsonSerializer.Deserialize<Transfer>(content),
				"file" => JsonSerializer.Deserialize<TransferData>(content),
				"disconnect" => JsonSerializer.Deserialize<Disconnect>(content),
				_ => throw new ArgumentException("Unknown message type.")
			};

		}
	}

}
