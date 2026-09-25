using System.Net;

namespace SODT_Server
{
	public static class SmartConsole
	{
		/// <summary>
		/// Gets or sets a value indicating whether to log messages to the console.
		/// </summary>
		public static bool Log { get; set; } = false;
		/// <summary>
		/// Writes a message to the console with a timestamp.
		/// </summary>
		/// <param name="message">Message to write to the console.</param>
		public static void WriteLine(string message)
		{
			if (Log)
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
			// Enable logging if the 'log' argument is passed.
			SmartConsole.Log = args.Contains("log");
			
			// Generate RSA key pair if they don't already exist or if the 'force-gen' argument is passed.
			bool forceRegeneration = args.Contains("force-gen");
			if (forceRegeneration)
			{
				SmartConsole.WriteLine("Force Key Regeneration");
				RSAEncryption.GenerateKeys(forceRegeneration);
				SmartConsole.WriteLine("New Keys generated. Restart the Server to use them.");
				return;
			}
			
			// Start the TCP server asynchronously on the loopback address and port 25565.
			var server = new AsyncTcpServer();
			await server.StartAsync(IPAddress.Any, 25565);
		}
	}
}