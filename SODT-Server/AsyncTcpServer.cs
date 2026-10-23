using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SODT_Server.SODT_Common;


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
		private readonly Dictionary<byte, AesGcm> aesSessionKeys = new();
		private readonly Dictionary<byte, ECDiffieHellman> ecdhSessionKeyGenerators = new();
		private readonly Dictionary<byte, DateTime> pingPongTimers = new();

		private readonly ECDsa serverCertificate = PersistentEcdsa.GetOrCreateEcdsa();
		
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
					_ = ClientConnectionMonitor(clientId); //fire and forget; monitor client connection
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
			byte[] buffer = new byte[MessageHelper.FullMessageSize];
			var client = clients[clientId];
			var stream = client.GetStream();

			// Listen for incoming data from the client in an infinite loop.
			while (client.Connected)
			{
				//wait until bufferSize bytes are received
				int bytesRead = 0;
				while (bytesRead < buffer.Length)
				{
					int read = await stream.ReadAsync(buffer.AsMemory(bytesRead));
					if (read == 0)
						return;
					bytesRead += read;
				}

				// Extract the message ID and payload from the incoming data.
				byte id = buffer[0];
				
				if (id == ServerId)
					await HandleServerMessage(Decrypt(buffer), clientId);
				else
					await SendToClient(id, buffer);

			}
			//close client connection properly
			await DisconnectClientInternal(clientId);
		}
		private IBaseMessage? Decrypt(Span<byte> buffer)
		{
			byte sourceId = buffer[1];
			// If the source client does not have an established AES session key, parse the message without decryption.
			if (!aesSessionKeys.TryGetValue(sourceId, out AesGcm? aes))
				return MessageHandler.ParseDecryptedMessage(buffer[MessageHelper.HeaderSizeWithoutContentLengthSize..]);
			// Decrypt the message using the established AES session key.
			Span<byte> decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			EncryptionHandler.DecryptAesGcm(aes, buffer, decryptedMessage);
			return MessageHandler.ParseDecryptedMessage(decryptedMessage);
		}
		
		/// <summary>
		/// Handles a message sent to the server.
		/// </summary>
		/// <param name="message">Received message</param>
		/// <param name="clientId">SourceId</param>
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
						await DisconnectClientInternal(clientId);
					break;
				case ClientList clientList:
					if (clientList.Code == (int)PacketCode.Request)
						await SendListToAllClients();
					break;
				case Disconnect:
					await DisconnectClientInternal(clientId);
					break;
				case PingPong pingPong:
					await HandlePingMessage(clientId, pingPong);
					break;
				case null:
					SmartConsole.WriteLine($"Client {clientId} sent an invalid message. Disconnecting client.");
					await SendToClientEncrypted(clientId, Disconnect.CreateRequest());
					await DisconnectClientInternal(clientId);
					break;
				default:
					SmartConsole.WriteLine("Unknown message type received. Ignoring message.");
					break;
			}
		}
		private async Task HandlePingMessage(byte clientId, PingPong pingPong)
		{
			switch(pingPong.Code)
			{
				case (int)PacketCode.Request:
					SmartConsole.WriteLine($"Received Ping from client {clientId}");
					pingPongTimers[clientId] = DateTime.Now;
					await SendToClientEncrypted(clientId, PingPong.CreateResponse());
					break;
				default:
					SmartConsole.WriteLine($"Unknown PingPong code received from client {clientId}. Ignoring message.");
					break;
			}
		}

		/// <summary>
		/// Monitors the connection of a client.
		/// IF the Client does not send a ping message for more than 10 seconds, the client will be disconnected.
		/// </summary>
		/// <param name="clientId">The ID of the client to monitor.</param>
		private async Task ClientConnectionMonitor(byte clientId)
		{
			while (clients.TryGetValue(clientId, out TcpClient? client) && client.Connected)
			{
				await Task.Delay(10000);

				pingPongTimers.TryGetValue(clientId, out DateTime lastPing);
				if ((DateTime.Now - lastPing).TotalSeconds < 10)
					continue;
				SmartConsole.WriteLine($"Client {clientId} is AFK for more than 10 seconds. Disconnecting client.");
				await SendToClientEncrypted(clientId, Disconnect.CreateRequest());
				await DisconnectClientInternal(clientId);
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
				await DisconnectClientInternal(targetId);
			}
		}
		
		private async Task SendToClientUnencrypted(byte targetId, Discovery baseMessage)
		{
			// create final message
			byte[] buffer = [targetId, ServerId, .. new byte[MessageHelper.NonceSize + MessageHelper.TagSize], ..baseMessage.ToBytes()];
			ReadOnlyMemory<byte> finalMessage = buffer;
			// send 
			await SendToClient(targetId, finalMessage);
		}
		
		private async Task SendToClientEncrypted(byte targetId, IBaseMessage baseMessage)
		{
			ReadOnlyMemory<byte> toSend;
			
			if (aesSessionKeys.TryGetValue(targetId, out AesGcm? aes))
			{
				byte[] finalMessage = new byte[MessageHelper.FullMessageSize];
				EncryptionHandler.EncryptAesGcm(aes, baseMessage, finalMessage);
				finalMessage[0] = targetId;
				finalMessage[1] = ServerId;
				toSend = finalMessage;
			}
			else
			{
				//This case should never happen because the CLI always checks and requests, if necessary, a key exchange before sending a message.
				SmartConsole.WriteLine($"No key for target client {targetId} to encrypt with. How do you even get here?");
				throw new InvalidOperationException("No key for target client to encrypt with.");
			}


			await SendToClient(targetId, toSend);
		}
		
		private async Task<bool> HandleDiscovery(byte clientId, Discovery discovery)
		{
			// create new ecdh session key generator for this client
			ecdhSessionKeyGenerators[clientId] = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			byte[] serverSessionPublicKey = ecdhSessionKeyGenerators[clientId].PublicKey.ExportSubjectPublicKeyInfo();
			
			// create aes session key for this client
			aesSessionKeys[clientId] = EncryptionHandler.GenerateSessionKey(ecdhSessionKeyGenerators[clientId], discovery.PublicKey);
			
			// sign the discovery message with the server certificate and send it back to the client
			byte[] toSign = [..discovery.PublicKey, ..serverSessionPublicKey, clientId];
			await SendToClientUnencrypted(clientId, Discovery.CreateResponse(clientId,serverSessionPublicKey,serverCertificate.SignData(toSign, HashAlgorithmName.SHA256)));
			return true;
		}
		
		/// <summary>
		/// Disconnects a client from the server.
		/// Sends an updated client list to all connected clients after the disconnection.
		/// </summary>
		/// <param name="clientId">Client to disconnect</param>
		/// <returns></returns>
		private async Task DisconnectClientInternal(byte clientId)
		{
			//dispose client
			if (clients.TryGetValue(clientId, out TcpClient? client))
				client.Close();
			if (ecdhSessionKeyGenerators.TryGetValue(clientId, out ECDiffieHellman? ecdh))
				ecdh.Dispose();
			if (aesSessionKeys.TryGetValue(clientId, out AesGcm? aes))
				aes.Dispose();

			//remove client from dictionaries
			_ = clients.Remove(clientId);
			_ = ecdhSessionKeyGenerators.Remove(clientId);
			_ = aesSessionKeys.Remove(clientId);
			_ = pingPongTimers.Remove(clientId);
			SmartConsole.WriteLine($"{clientId} disconnected from server.");
			SmartConsole.WriteLine("Update client list for all clients.");
			await SendListToAllClients();
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
				//if a client is not connected, SendToClientUnencrypted will throw an exception and the client will be disconnected
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