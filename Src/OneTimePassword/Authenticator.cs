using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public abstract class Authenticator
    {
        public abstract OneTimePassword GeneratePassword(OneTimePasswordAccount account); 
        internal virtual string TruncatePassword(uint fullCode,int length) // This is needed to support Authenticators like Steam which are based on OATH
        {
            return (fullCode % Math.Pow(10, length)).ToString().PadLeft(length, '0');
        }

    }
}
