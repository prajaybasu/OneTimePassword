//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public static class Extensions
    {
        internal static HMAC GetHmac(this HashAlgorithmName name)
        {
            if (name == HashAlgorithmName.MD5)
            {
                return new HMACMD5();
            }
            else if (name == HashAlgorithmName.SHA1)
            {
                return new HMACSHA1();
            }
            else if (name == HashAlgorithmName.SHA256)
            {
                return new HMACSHA256();
            }
            else if (name == HashAlgorithmName.SHA384)
            {
                return new HMACSHA384();
            }
            else if(name == HashAlgorithmName.SHA512)
            {
                return new HMACSHA512();
            }
            else throw new InvalidOperationException("Invalid Algorithm");
        }
        /// <summary>
        /// Returns a truncated string as per the RFC documents.
        /// </summary>
        /// <param name="fullCode"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        internal static string ToTruncatedString(this uint fullCode, int length)
        {
            Contract.Requires<InvalidOperationException>(length > 0, "Length cannot be less than zero.");
            return (fullCode % Math.Pow(10, length)).ToString().PadLeft(length, '0');
        }
        /// <summary>
        /// Returns a truncated string as used by Steam.
        /// </summary>
        /// <param name="fullCode"></param>
        /// <returns></returns>
        internal static string ToSteamTruncatedString(this uint fullCode)
        {
            char[] steamAlphanumerics = new char[] { '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C','D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q','R', 'T', 'V', 'W', 'X', 'Y' };
            string code = fullCode.ToString();
            for (var i = 0; i < 5; i++)
            {
                code += steamAlphanumerics[fullCode % 5];
                fullCode /= 5;
            }
            return code;
        }
        internal static DateTimeOffset TryAlignToValveTime(this DateTimeOffset offset)
        {
            DateTimeOffset serverTime = DateTimeOffset.UtcNow;
            using (var client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(2);
                try
                {
                    dynamic content = JObject.Parse(client.PostAsync("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001", null).Result.Content.ToString()); // Oh Valve, the master of RESTful APIs 
                    serverTime = DateTimeOffset.FromUnixTimeSeconds(content.response.server_time);
                }
                catch(Exception)
                {
                    serverTime = DateTimeOffset.UtcNow;
                }
            }
            return serverTime;
        }
    }
}
