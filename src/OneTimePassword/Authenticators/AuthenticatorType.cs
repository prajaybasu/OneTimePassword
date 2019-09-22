using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace OneTimePassword.Authenticators
{
    public enum AuthenticatorType
    {
        [EnumMember(Value = "hotp")]
        HOTP,

        [EnumMember(Value = "totp")]
        TOTP,

        [EnumMember(Value = "steam")]
        Steam
    }
}
