using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace SimpleJWT.Providers
{
    public class MembershipProvider
    {

        public List<Claim> Claims = new List<Claim>();


        public List<Claim> GetUserClaims(string username)
        {
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
