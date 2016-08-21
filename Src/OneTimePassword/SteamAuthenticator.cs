using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public class SteamAuthenticator : TimeBasedAuthenticator
    {
        #region Implementation
        public override OneTimePassword GeneratePassword(OneTimePasswordAccount account)
        {
            return new OneTimePassword(GeneratePassword(account.Secret, DateTimeOffset.Now), DateTimeOffset.Now.Add(account.Period).Date);
        }
        /// <summary>
        /// Returns a truncated string as used by Steam.
        /// </summary>
        /// <param name="fullCode"></param>
        /// <returns></returns>
        internal override string TruncatePassword(uint fullCode, int length = 5)
        {
            char[] steamAlphanumerics = new char[] { '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y' };
            string code = fullCode.ToString();
            for (var i = 0; i < length; i++)
            {
                code += steamAlphanumerics[fullCode % steamAlphanumerics.Length];
                fullCode /= (uint)steamAlphanumerics.Length;
            }
            return code;
        }
        #endregion
        #region Static Functions
        public static string GeneratePassword(byte[] secret, DateTimeOffset time)
        {
            return GenerateFullCode(new HMACSHA1(), secret, time.TryAlignToValveTime(), TimeSpan.FromSeconds(30)).ToSteamTruncatedString();
        }
        #endregion
        #region Hidden members
        [Obsolete("Use the public implementation.",true)]
        private new string GeneratePassword(int length, HMAC hmac, byte[] secret, DateTimeOffset time, TimeSpan period)
        {
            throw new NotImplementedException();
        }
        [Obsolete("Use the public implementation.", true)]
        private new string GeneratePassword(long counter, int length, HMAC hmac, byte[] secret)
        {
            throw new NotImplementedException();
        }
        [Obsolete("Use the public implementation.", true)]
        internal new static uint GenerateFullCode(long counter, HMAC hmac, byte[] secret)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
