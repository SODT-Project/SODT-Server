using System.Text;
using System.Text.Json;

namespace SODT_Server
{
	/// <summary>
	/// Represents a message handler class that can parse and send messages over a network stream.
	/// </summary>
	public class MessageHandler //TODO make this static
	{

		/// <summary>
		/// Parses a message packet received from a client into a <see cref="IBaseMessage"/> object.
		/// </summary>
		/// <param name="messageWithContentSize"> Decrypted message packet received from the client.</param>
		/// <returns> The parsed <see cref="IBaseMessage"/> message object or <see langword="null"/> if parsing fails.</returns>
		public static IBaseMessage? ParseDecryptedMessage(byte[] messageWithContentSize) // TODO make this better type like Span
		{
			try
			{
				ushort length = BitConverter.ToUInt16(messageWithContentSize[0..2], 0); // TODO remove magic numbers
				string messageJson = Encoding.UTF8.GetString(messageWithContentSize[2..(length + 2)]);
				return HandleType(messageJson);
			}
			catch (Exception ex)
			{
				// Handle any JSON formatting errors that occur during deserialization.
				SmartConsole.WriteLine($"Error while Parsing: {ex.Message}");
				return null;
			}
		}
		/// <summary>
		/// Handles a message of an unknown type.
		/// </summary>
		/// <param name="messageJson">The JSON representation of the message.</param>
		/// <returns>The deserialized message object parsed wrapped in an <see cref="IBaseMessage"/> object.</returns>
		private static IBaseMessage HandleType(string messageJson)
		{
			return JsonSerializer.Deserialize<BaseMessage>(messageJson).Type switch
			{
				"discovery" => JsonSerializer.Deserialize<Discovery>(messageJson),
				"exchange" => JsonSerializer.Deserialize<KeyExchange>(messageJson),
				"disconnect" => JsonSerializer.Deserialize<Disconnect>(messageJson),
				"clients" => JsonSerializer.Deserialize<ClientList>(messageJson),
				_ => throw new ArgumentException("Unknown message type.")
			};

		}
	}

}
