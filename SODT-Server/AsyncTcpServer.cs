using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;


namespace SODT_Server
{
	/// <summary>
	/// Represents an asynchronous TCP server.
	/// </summary>
	public class AsyncTcpServer
	{
		private const byte ServerId = 1;

		/// <summary>
		/// A dictionary of connected clients, keyed by their unique IDs.
		/// </summary>
		private readonly Dictionary<byte, TcpClient> clients = new();

		/// <summary>
		/// A dictionary of session keys for each client, keyed by their unique IDs.
		/// </summary>
		private readonly Dictionary<int, AesGcm> clientServerSessionKeys = new();

		/// <summary>
		/// Server's RSA encryption key pair.
		/// </summary>
		private readonly RSA serverRsaEncryption = RsaEncryption.Create();

		/// <summary>
		/// Buffer size for incoming data.
		/// </summary>
		private const int BufferSize = MessageHelper.FullMessageSize;

		/// <summary>
		/// Starts the TCP server on the specified IP address and port.
		/// And listens for incoming client connections continuously.
		/// </summary>
		/// <param name="ipAddress">The IP address to bind the server to.</param>
		/// <param name="port">The port number to use for the server.</param>
		/// <returns> A Task representing the asynchronous operation.</returns>
		public async Task StartAsync(IPAddress ipAddress, int port)
		{
			// Create a new TcpListener instance and start listening on the specified IP address and port.
			TcpListener listener = new TcpListener(ipAddress, port);
			listener.Start();
			SmartConsole.WriteLine($"Server started on {ipAddress}:{port}");

			// Initialize a counter to generate unique client IDs.
			byte clientId = 2;

			// Listen for incoming client connections in an infinite loop.
			while (true)
			{
				try
				{
					var client = await listener.AcceptTcpClientAsync();

					// handle full server:
					while (clients.Count >= byte.MaxValue - 1)
					{
						SmartConsole.WriteLine("Server is full. Blocking new connections until a client disconnects.");
						await Task.Delay(1000);
					}
					// Find next available client ID (2-255) for the new client.
					// This loop will always find an available ID because the server is not full.
					for (byte i = 2; i < byte.MaxValue; i++)
					{
						if (!clients.ContainsKey(i))
						{
							clientId = i;
							break;
						}
					}
					
					// Add the new client to the dictionary of connected clients.
					clients[clientId] = client;
					SmartConsole.WriteLine($"New client connected. Assigned id: {clientId}");
					_ = HandleClientAsync(clientId); //fire and forget; client handles itself
				}
				catch (Exception e)
				{
					SmartConsole.WriteLine($"{DateTime.Now}: FATAL ERROR! Server terminated!");
					SmartConsole.WriteLine(e.ToString());
					break;
				}
			}
			listener.Stop();
		}

		/// <summary>
		/// Handles a single incoming client connection asynchronously until the client disconnects.
		/// </summary>
		/// <param name="clientId">The ID of the connected client.</param>
		private async Task HandleClientAsync(byte clientId)
		{
			byte[] buffer = new byte[BufferSize];
			var client = clients[clientId];
			var stream = client.GetStream();

			// Listen for incoming data from the client in an infinite loop.
			while (client != null && client.Connected)
			{
				//wait unitil bufferSize bytes are received
				while (stream.Socket.Available < BufferSize)
				{
					//delay to reduce cpu usage
					await Task.Delay(50);

					//check if client is still connected
					if (client == null || !client.Connected)
					{
						await DisconnectClient(clientId, Disconnect.CreateRequest());
						return;
					}
				}

				// Read the incoming data from the client into the buffer.
				int bytesRead = await stream.ReadAsync(buffer);

				// Extract the message ID and payload from the incoming data.
				byte id = buffer[0];

				// If the message is meant for the server, handle it accordingly.
				if (id == ServerId)
				{
					var message = Decrypt(clientId, buffer);
					await HandleServerMessage(message, clientId);
					continue;
				}
				// Otherwise, redirect the message to the corresponding client.
				await SendToClient(id, buffer);

			}
			//close client connection properly
			await DisconnectClient(clientId, Disconnect.CreateRequest());
		}
		/// <summary>
		/// Decrypts a message from a client.
		/// </summary>
		/// <param name="clientId"> The ID of the client that sent the message.</param>
		/// <param name="message"> The encrypted message to decrypt. Without target and source Id bytes.</param>
		/// <returns>The decrypted message as an <see cref="IBaseMessage"/> object or <see langword="null"/> if decryption fails.</returns>
		private IBaseMessage? Decrypt(byte clientId, ReadOnlySpan<byte> message)
		{
			//decrypt message
			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			//special case for discovery (aka if no session key or aes is null)
			if (!clientServerSessionKeys.TryGetValue(clientId, out AesGcm? aes) || aes == null)
			{
				//decrypt
				try
				{
					decryptedMessage = serverRsaEncryption.Decrypt(message[2..514], RSAEncryptionPadding.Pkcs1);
				}
				catch
				{
					SmartConsole.WriteLine($"Discovery failed for client {clientId}.");
					return null;
				}
			}
			else
			{
				EncryptionHandler.DecryptAesGcm(aes, message, decryptedMessage);
			}
			return MessageHandler.ParseDecryptedMessage(decryptedMessage);
		}

		/// <summary>
		/// Handles a message sent to the server.
		/// </summary>
		/// <param name="message">Received message</param>
		/// <param name="clientId">Source Id</param>
		/// <returns> A Task representing the asynchronous operation.</returns>
		private async Task HandleServerMessage(IBaseMessage? message, byte clientId)
		{
			switch (message)
			{
				case Discovery discovery:
					bool isDiscoverySuccessful = await HandleDiscovery(clientId, discovery);
					if (isDiscoverySuccessful)
						await SendListToAllClients();
					else
						await DisconnectClient(clientId, Disconnect.CreateRequest());
					break;
				case ClientList clientList:
					if (clientList.Code == (int)PacketCode.Request)
						await SendListToAllClients();
					break;
				case KeyExchange keyExchange:
					bool isExchangeSuccessful = await HandleExchange(keyExchange);
					//send error message to all affected clients
					if (!isExchangeSuccessful)
					{
						KeyExchange keyExchangeError = KeyExchange.CreateError(keyExchange);
						await SendToClientEncrypted(keyExchange.SourceId, keyExchangeError);
						await SendToClientEncrypted(keyExchange.TargetId, keyExchangeError);
					}
					break;
				case Disconnect disconnect:
					await DisconnectClient(clientId, disconnect);
					await SendListToAllClients();
					break;
				case null:
					SmartConsole.WriteLine($"Client {clientId} sent an invalid message. Disconnecting client.");
					await DisconnectClient(clientId, Disconnect.CreateRequest());
					break;
				default:
					SmartConsole.WriteLine("Unknown message type received. Ignoring message.");
					break;
			}
		}

		/// <summary>
		/// Sends a message to a connected client asynchronously.
		/// </summary>
		/// <param name="targetId">The ID of the client to send the message to.</param>
		/// <param name="message">The message payload to be sent.</param>
		private async Task SendToClient(byte targetId, ReadOnlyMemory<byte> message)
		{
			try
			{
				// Retrieve the TcpClient instance for the specified client from the dictionary.
				TcpClient tcpClient = clients[targetId];
				var stream = tcpClient.GetStream();
				await stream.WriteAsync(message);
			}
			catch (Exception e)
			{
				SmartConsole.WriteLine($"Sending Message to {targetId} failed. Cause: {e.Message}");
				SmartConsole.WriteLine($"Disconnecting client {targetId}");
				await DisconnectClient(targetId, new Disconnect() { Code = 401 });
			}
		}

		/// <summary>
		/// Encrypts a message with the client's session key and sends it to the client asynchronously.
		/// </summary>
		/// <param name="targetId">Target Client</param>
		/// <param name="baseMessage">Message</param>
		/// <returns></returns>
		private async Task SendToClientEncrypted(byte targetId, IBaseMessage baseMessage)
		{
			if (clientServerSessionKeys.TryGetValue(targetId, out AesGcm? encryption) && encryption != null)
			{
				// create final message
				byte[] finalMessage = new byte[MessageHelper.FullMessageSize];
				finalMessage[0] = ServerId;
				finalMessage[1] = targetId;
				
				// insert encrypted message into final message
				EncryptionHandler.EncryptAesGcm(encryption, baseMessage, finalMessage);
				
				// send 
				await SendToClient(targetId, finalMessage);
			}
			else
			{
				SmartConsole.WriteLine($"Client {targetId} has no session key. Disconnecting client.");
				await DisconnectClient(targetId, Disconnect.CreateRequest());
			}
		}

		/// <summary>
		/// Handles a discovery message, including generating a response with encrypted data.
		/// </summary>
		/// <param name="clientId">Client Id assigned by server.</param>
		/// <param name="discovery">Clients discovery request.</param>
		/// <returns></returns>
		private async Task<bool> HandleDiscovery(byte clientId, Discovery discovery)
		{
			if (discovery.Key == null || discovery.Iv == null || discovery.Code != (int)PacketCode.Request)
			{
				return false;
			}
			//add client to clients dictionary already done in StartAsync

			//add encryption key to keys dictionary
			var aes = new AesGcm(discovery.Key, MessageHelper.TagSize);
			clientServerSessionKeys.Add(clientId, aes);

			//send client verification message with their targetId
			await SendToClientEncrypted(clientId, Discovery.CreateResponse(clientId));
			return true;
		}

		/// <summary>
		/// Handles a key exchange message.
		/// This Message is used to establish a secure connection between two clients. <br></br>
		/// This method redirects the key to the target client.
		/// The key exchange request was decrypted by the server and will be encrypted by the server before sending it to the target client.
		/// </summary>
		/// <param name="keyExchange">keyExchange message</param>
		/// <returns></returns>
		private async Task<bool> HandleExchange(KeyExchange keyExchange)
		{
			if (keyExchange.Key == null || !clientServerSessionKeys.ContainsKey(keyExchange.TargetId))
			{
				return false;
			}
			//redirect key to target client
			await SendToClientEncrypted(keyExchange.TargetId, keyExchange);
			return true;
		}

		/// <summary>
		/// Disconnects a client from the server.
		/// </summary>
		/// <param name="clientId">Client to disconnect</param>
		/// <param name="disconnect">Disconnect message</param>
		/// <returns></returns>
		private async Task DisconnectClient(byte clientId, Disconnect disconnect)
		{
			//Dispose session key
			if (clientServerSessionKeys.TryGetValue(clientId, out AesGcm? aes))
				aes.Dispose();
			//dispose client
			if (clients.TryGetValue(clientId, out TcpClient? client))
				client.Dispose();
			//remove client from dictionaries
			_ = clients.Remove(clientId);
			_ = clientServerSessionKeys.Remove(clientId);
			SmartConsole.WriteLine($"{clientId} disconnected from server.");
		}

		/// <summary>
		/// This method sends a list of currently connected clients to all clients.
		/// </summary>
		/// <returns>A Task representing the asynchronous operation.</returns>
		private async Task SendListToAllClients()
		{
			//check if all clients are still connected and remove disconnected clients
			foreach (var client in clients)
			{
				//check if client is still connected
				//if a client is not connected, SendToClientEncrypted will throw an exception and the client will be disconnected
				await SendToClientEncrypted(client.Key, ClientList.CreateRequest());
			}

			//send list to all clients
			ClientList clientList = ClientList.CreateResponse(clients.Keys.ToArray());
			foreach (var client in clients)
			{
				await SendToClientEncrypted(client.Key, clientList);
			}
		}
	}
}