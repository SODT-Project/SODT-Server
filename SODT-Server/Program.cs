using System.Net;

namespace SODT_Server
{
	public static class SmartConsole
	{
		/// <summary>
		/// Writes a message to the console with a timestamp.
		/// </summary>
		/// <param name="message">Message to write to the console.</param>
		public static void WriteLine(string message)
		{
			Console.WriteLine($"{DateTime.Now}: {message}");
		}
	}

	/// <summary>
	/// The main entry point for the application.
	/// </summary>
	public class Program
	{
		/// <summary>
		/// Main method, which creates a new instance of the AsyncTcpServer and starts it asynchronously.
		/// following arguments are supported: 
		/// <br>force-gen: force regeneration of RSA keys</br>
		/// <br>log: enable logging</br>
		/// </summary>
		public static async Task Main(string[] args)
		{
			// Generate RSA key pair if they don't already exist or if the 'force-gen' argument is passed.
			bool forceRegeneration = args.Contains("force-gen");
			if (forceRegeneration)
			{
				SmartConsole.WriteLine("Force Key Regeneration");
				PersistentEcdsa.ForceRegenerateEcdsa();
				SmartConsole.WriteLine("New Keys generated. Restart the Server to use them.");
				return;
			}
			
			string listenIp = Environment.GetEnvironmentVariable("SODT_LISTEN_IP") ?? "0.0.0.0";
			if (!IPAddress.TryParse(listenIp, out var ipAddress))
				throw new ArgumentException($"SODT_LISTEN_IP is not a valid IP address: {listenIp}");

			string listenPortValue = Environment.GetEnvironmentVariable("SODT_LISTEN_PORT") ?? "45645";
			if (!int.TryParse(listenPortValue, out int port) || port is < 1 or > 65535)
				throw new ArgumentException($"SODT_LISTEN_PORT must be between 1 and 65535: {listenPortValue}");

			// Start the TCP server asynchronously using the configured bind address and port.
			var server = new AsyncTcpServer();
			await server.StartAsync(ipAddress, port);
		}
	}
}