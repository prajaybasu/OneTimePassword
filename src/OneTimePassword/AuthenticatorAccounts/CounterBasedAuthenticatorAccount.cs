using OneTimePassword.Authenticators;
using OneTimePassword.Utilities;
using System;

namespace OneTimePassword.AuthenticatorAccounts
{
    public class CounterBasedAuthenticatorAccount : AuthenticatorAccount
    {
        /// <summary>
        /// The 8 byte counter value
        /// </summary>
        public byte[] Counter { get; set; } = BitConverter.GetBytes(0UL);

        public new Authenticator Authenticator => new CounterBasedAuthenticator();

        /// <summary>
        /// Generates a one time password using the given parameters.
        /// </summary>
        new public OneTimePassword GeneratePassword() => (Authenticator as CounterBasedAuthenticator).GeneratePassword(this);

        public override string ToString()
        {
            var digits = (PasswordLength == 6) ? "" : $"&digits={PasswordLength}";
            var algorithm = (HashAlgorithm.Name == "SHA1") ? "" : $"&algorithm={HashAlgorithm.Name.ToLower()}";
            algorithm = algorithm.Replace("sha256", "sha2");
            var counter = (BitConverter.ToUInt64(Counter, 0) == 0UL) ? "" : $"&counter={BitConverter.ToUInt64(Counter, 0)}";
            var issuer = (string.IsNullOrEmpty(Issuer)) ? "" : $"&issuer={Uri.UnescapeDataString(Issuer)}";
            return $"otpauth://hotp/{Uri.EscapeDataString(Label)}?secret={Base32Encoding.GetString(Secret)}{counter}{digits}{algorithm}{issuer}";
        }
    }
}
