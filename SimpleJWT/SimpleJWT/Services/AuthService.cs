﻿using SimpleJWT.Providers;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using System.Diagnostics;
using System.IO;

namespace SimpleJWT.Services
{
    public class AuthService
    {
        private readonly MembershipProvider _membershipProvider;
        private readonly RSAKeyProvider _rsaProvider;

        public AuthService()
        {
            _membershipProvider = new MembershipProvider();
            _rsaProvider = new RSAKeyProvider();
        }

        public async Task<string> GenerateJwtTokenAsync(string username, string password)
        {
            if (!_membershipProvider.VerifyUserPassword(username, password))
                return "Wrong access";

            var claims = _membershipProvider.GetUserClaims(username);

            var publicAndPrivateKey = await _rsaProvider.GetPrivateAndPublicKeyAsync();
            
            RSACryptoServiceProvider PrivateKey = new RSACryptoServiceProvider(2048);
            RSAKeyExtensions.FromXmlString(PrivateKey, publicAndPrivateKey.priv);
            IdentityModelEventSource.ShowPII = true;
            JwtSecurityToken jwtToken = new JwtSecurityToken
            (
                issuer: "http://issuer.com",
                audience: "http://mysite.com",
                claims: claims,
                signingCredentials: new SigningCredentials(new RsaSecurityKey(PrivateKey), SecurityAlgorithms.RsaSha256Signature),
                expires: DateTime.Now.AddDays(30)
            );
            
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            string tokenString = tokenHandler.WriteToken(jwtToken);
            await SaveToken(tokenString);
            return tokenString;
        }


        private async Task SaveToken(String Token)
        {
            var folder = AppDomain.CurrentDomain.BaseDirectory + @"RsaKeys";
            try
            {
                using (StreamWriter fileStream = File.CreateText(Path.Combine(folder, "Token.json")))
                {
                    await fileStream.WriteLineAsync(Token);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }

        public async Task<bool> ValidateTokenAsync(string TokenString)
        {
            Boolean result = false;

            try
            {
                SecurityToken securityToken = new JwtSecurityToken(TokenString);
                JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();
                RSACryptoServiceProvider publicAndPrivate = new RSACryptoServiceProvider(2048);

                var publicAndPrivateKey = await _rsaProvider.GetPrivateAndPublicKeyAsync();

                RSAKeyExtensions.FromXmlString(publicAndPrivate,publicAndPrivateKey.pub);

                TokenValidationParameters validationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = "http://issuer.com",
                    ValidAudience = "http://mysite.com",
                    IssuerSigningKey = new RsaSecurityKey(publicAndPrivate)
                };

                ClaimsPrincipal claimsPrincipal = securityTokenHandler.ValidateToken(TokenString, validationParameters, out securityToken);

                result = true;
            }
            catch (Exception ex)
            {
                result = false;
            }

            return result;
        }
    }
}
