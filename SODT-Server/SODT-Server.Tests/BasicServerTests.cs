using System.Net;
using SODT_Server;

namespace SODT_Server.Tests
{
	public class BasicServerTests
	{
		[Fact]
		public async Task StartServer()
		{
			AsyncTcpServer server = new();
			var task = server.StartAsync(IPAddress.Any, 45645);
			await Task.Delay(1000); // wait for 1 second to let the server start
			Assert.True(task != null && !task.IsFaulted, "Server failed to start.");
		}
	}
}