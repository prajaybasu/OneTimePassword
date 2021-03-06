﻿using OneTimePassword.Authenticators;
using OneTimePassword.Utilities;
using System;

namespace OneTimePassword.AuthenticatorAccounts
{
    public class TimeBasedAuthenticatorAccount : AuthenticatorAccount
    {
        /// <summary>
        /// It defines the validity of the OTP issued.
        /// </summary>
        public TimeSpan Period { get; set; } = TimeSpan.FromSeconds(30);

        public new Authenticator Authenticator => new TimeBasedAuthenticator();

        /// <summary>
        /// Generates a one time password using the given parameters.
        /// </summary>
        new public OneTimePassword GeneratePassword() => (Authenticator as TimeBasedAuthenticator).GeneratePassword(this);

        /// <summary>
        /// Generates a one time password using the given parameters.
        /// </summary>
        public OneTimePassword GeneratePassword(DateTimeOffset time) => (Authenticator as TimeBasedAuthenticator).GeneratePassword(this, time);

        public override string ToString()
        {
            var digits = (PasswordLength == 6) ? "" : $"&digits={PasswordLength}";
            var algorithm = (HashAlgorithm.Name == "SHA1") ? "" : $"&algorithm={HashAlgorithm.Name.ToLower()}";
            algorithm = algorithm.Replace("sha256", "sha2");
            var period = (Period.TotalSeconds == 30) ? "" : $"&period={Period.TotalSeconds}";
            var issuer = (string.IsNullOrEmpty(Issuer)) ? "" : $"&issuer={Uri.UnescapeDataString(Issuer)}";
            return $"otpauth://totp/{Uri.UnescapeDataString(Label)}?secret={Base32Encoding.GetString(Secret)}{period}{algorithm}{digits}{issuer}";
        }
    }
}
