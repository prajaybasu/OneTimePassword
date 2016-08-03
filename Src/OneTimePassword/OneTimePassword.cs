using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public class OneTimePassword
    {
        public DateTime ValidUntilUtc { get; internal set; }
        public string Password { get; internal set; }
        public OneTimePassword(string password,DateTime validUntilUtc)
        {
            Password = password;
            ValidUntilUtc = validUntilUtc;
        }
    }
}
