using SimpleJWT.Services;
using System;

namespace SimpleJWT
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "JWT Creator";
            var aService = new AuthService();

            var token = aService.GenerateJwtTokenAsync("bay", "mill").Result;

            Console.WriteLine($"Token value:\n{token}");


            var result = aService.ValidateTokenAsync(token).Result;
            Console.WriteLine($"Token Status: {result}");

            Console.WriteLine("Press any key to exit . . .");
            Console.ReadKey();
        }
    }
}
