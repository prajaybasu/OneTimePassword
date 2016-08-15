using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public class SteamAuthenticator
    {
        public static string GeneratePassword(byte[] secret, DateTimeOffset time)
        {
            return TimeBasedAuthenticator.GenerateFullCode(new HMACSHA1(), secret, time.TryAlignToValveTime(), TimeSpan.FromSeconds(30)).ToSteamTruncatedString();
        }
    }
}
