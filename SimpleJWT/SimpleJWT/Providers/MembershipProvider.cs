using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace SimpleJWT.Providers
{
    public class MembershipProvider
    {
        public List<Claim> GetUserClaims(string username)
        {
            List<Claim> Claims = new List<Claim>();
            Claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            Claims.Add(new Claim(ClaimTypes.Email, "baileymiller@live.com"));
            return Claims;
        }

        public bool VerifyUserPassword(string username, string password)
        {
            if (username == "bay" && password == "mill")
                return true;
            return false;
        }
    }
}
