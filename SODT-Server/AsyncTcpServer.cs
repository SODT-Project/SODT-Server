using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SODT_Common;


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

		private readonly ECDsa serverCertificate = PersistentEcdsa.GetOrCreateEcdsa();
		
		/// <summary>
		/// Buffer size for incoming data.
		/// </summary>
		private const int BufferSize = MessageHelper.FullMessageSize;

		// Initialize the server certificate (for signing messages).
		// In a real-world application, you would load a persistent certificate from a secure location.
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
					var message = MessageHandler.ParseDecryptedMessage(buffer.AsSpan()[MessageHelper.HeaderSizeWithoutContentLengthSize..]);
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
		
		
		private async Task SendToClientUnencrypted(byte targetId, IBaseMessage baseMessage)
		{
			// create final message
			byte[] finalMessage = new byte[MessageHelper.FullMessageSize];
			finalMessage[0] = targetId;
			finalMessage[1] = ServerId;
			
			// insert unencrypted message into final message
			Array.Copy(baseMessage.ToBytes(), 0, finalMessage, MessageHelper.HeaderSizeWithoutContentLengthSize, MessageHelper.MessageWithContentSize); // TODO fix
			
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
				//This case should never happen because the CLI always checks and requests, if neccessary, a key exchange before sending a message.
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
			
			// sign the discovery message with the server certificate and send it back to the client
			byte[] toSign = [..discovery.PublicKey, ..serverSessionPublicKey, clientId];
			await SendToClientUnencrypted(clientId, Discovery.CreateResponse(clientId,serverSessionPublicKey,serverCertificate.SignData(toSign, HashAlgorithmName.SHA256)));
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
			//dispose client
			if (clients.TryGetValue(clientId, out TcpClient? client))
				client.Dispose();
			//remove client from dictionaries
			_ = clients.Remove(clientId);
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
				//if a client is not connected, SendToClientUnencrypted will throw an exception and the client will be disconnected
				await SendToClientUnencrypted(client.Key, ClientList.CreateRequest());
			}

			//send list to all clients
			ClientList clientList = ClientList.CreateResponse(clients.Keys.ToArray());
			foreach (var client in clients)
			{
				await SendToClientUnencrypted(client.Key, clientList);
			}
		}
	}
}