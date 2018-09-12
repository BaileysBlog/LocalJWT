using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleJWT.Services;
using System.Threading.Tasks;
using System.Linq;

namespace StatelessFileAccessPermission
{
    [TestClass]
    public class StatelessTests
    {


        /*
         * Things to pretend
         *  1) Each test is a new process that was launched with the Token passed into it
         *  2) That the public key is acquired via a web api not the local file system
         *  3) That the files being accessed are on a remote system not the local system
         */

        AuthService AuthenticationService = new AuthService();

        [TestMethod]
        public async Task AccessFileFromJWT()
        {
            AuthenticationService.AddClaim("File-Read", @"C:\Users\Bailey Miller\Desktop\Fortnite Edited Videos\TeleportingKid.mp4");



            var statelessToken = await AuthenticationService.GenerateJwtTokenAsync("bay","mill");

            var hasFileRead = AuthenticationService.GetTokenClaims(statelessToken).Count(x=>x.Type == "File-Read") != 0;

            Assert.IsTrue(hasFileRead, "Token is expected to have 'File-Read' claim attached");
        }

        [TestMethod]
        public async Task ChangingTokenMakesItInvalid()
        {
            var statelessToken = await AuthenticationService.GenerateJwtTokenAsync("bay", "mill");

            Assert.IsTrue(await AuthenticationService.ValidateTokenAsync(statelessToken),"Token was expeceted to be valid");

            statelessToken += statelessToken;

            Assert.IsFalse(await AuthenticationService.ValidateTokenAsync(statelessToken),"Token was expected to be invalid");

        }
    }
}
