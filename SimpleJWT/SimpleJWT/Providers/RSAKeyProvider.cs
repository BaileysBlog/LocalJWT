using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SimpleJWT.Providers
{
    public class RSAKeyProvider
    {
        private string PublicRsaKeyPath;
        private string PrivateRsaKeyPath;

        public RSAKeyProvider()
        {
            var folder = AppDomain.CurrentDomain.BaseDirectory + @"RsaKeys";
            Directory.Delete(folder, true);
            Directory.CreateDirectory(folder);

            PublicRsaKeyPath = folder + @"\RsaPublicKey.txt";
            PrivateRsaKeyPath = folder + @"\RsaPrivateKey.txt";
        }

        public async Task<(String priv, String pub)> GetPrivateAndPublicKeyAsync()
        {
            var keys = await GetStoredKeyValues();
            if (string.IsNullOrEmpty(keys.priv) || String.IsNullOrEmpty(keys.pub))
            {
                keys = CreatePrivateAndPublicKey();
                await StoreKeyValues(keys.priv, keys.pub);
            }
            var areSame = keys.priv == keys.pub;
            return keys;
        }

        private (String priv, String pub) CreatePrivateAndPublicKey()
        {

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.ExportParameters(false);
                    string pubKey = RSAKeyExtensions.ToXmlString(rsa, false);
                    rsa.ExportParameters(true);
                    string privKey = RSAKeyExtensions.ToXmlString(rsa, true);

                    return (privKey, pubKey);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            
        }

        private async Task<Boolean> StoreKeyValues(String privKey, String pubKey)
        {
            
            try
            {
                using (StreamWriter fileStream = File.CreateText(PublicRsaKeyPath))
                {
                    await fileStream.WriteLineAsync(pubKey);
                }

                using (StreamWriter fileStream = File.CreateText(PrivateRsaKeyPath))
                {
                    await fileStream.WriteLineAsync(privKey);
                }
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                return false;
            }
        }

        private async Task<(String priv, String pub)> GetStoredKeyValues()
        {
            var privKey = "";
            var pubKey = "";
            try
            {
                using (var fs = new StreamReader((Stream)File.OpenRead(PublicRsaKeyPath)))
                {
                    pubKey = await fs.ReadToEndAsync();
                }

                using (var fs = new StreamReader((Stream)File.OpenRead(PrivateRsaKeyPath)))
                {
                    privKey = await fs.ReadToEndAsync();
                }

                
            }
            catch (Exception error)
            {
            }

            return (privKey, pubKey);
        }

    }

}
