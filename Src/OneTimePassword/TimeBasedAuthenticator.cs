using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public static class TimeBasedAuthenticator
    {
        internal static readonly DateTime UnixEpochUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static string GeneratePassword(int length, HMAC hmac, byte[] secret, DateTimeOffset time, TimeSpan period)
        {
            return CounterBasedAuthenticator.GeneratePassword((long) (time.ToUnixTimeSeconds()/period.TotalSeconds), length,hmac,secret);
        }
    }
}
