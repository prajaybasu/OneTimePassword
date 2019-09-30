//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Linq;
using System.Security.Cryptography;
using OneTimePassword.Authenticators;
using OneTimePassword.Utilities;

namespace OneTimePassword.AuthenticatorAccounts
{
    //https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    public abstract class AuthenticatorAccount
    {
        #region Properties

        /// <summary>
        /// The name of the account.
        /// </summary>
        public string Name { get; set; } = "";

        /// <summary>
        /// Type of Authenticator to use for the account.
        /// <seealso cref="AuthenticatorType"/>
        /// </summary>
        public AuthenticatorType AuthenticatorType { get; set; } = AuthenticatorType.TOTP;

        /// <summary>
        /// The label of the account.
        /// </summary>
        public string Label { get => String.IsNullOrEmpty(Issuer) ? Name : $"{Issuer}:{Name}"; }

        /// <summary>
        /// The name of the organization or company the account belongs to.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// The account secret used to generate OTP codes.
        /// </summary>
        public byte[] Secret { get; set; }

        /// <summary>
        ///  The algorithm to be used when generating the one time password.
        ///  <seealso cref="HashAlgorithmName"/>
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA1;

        /// <summary>
        /// The length of the password.
        /// </summary>
        public uint PasswordLength { get; set; } = 6;

        #endregion

        protected AuthenticatorAccount ()
        {
            Secret = new byte[20];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(Secret, 0, 20); // RFC 4226 Section 4 recommends 160 bits shared secret
            }
        }

        public virtual Authenticator Authenticator
        {
            get
            {
                switch (AuthenticatorType)
                {
                    case AuthenticatorType.HOTP:
                        return new CounterBasedAuthenticator();
                    case AuthenticatorType.Steam:
                        return new SteamAuthenticator();
                    default:
                        return new TimeBasedAuthenticator();
                }
            }
        }

        /// <summary>
        /// Generates a one time password using the given parameters.
        /// </summary>
        public OneTimePassword GeneratePassword() => Authenticator.GeneratePassword(this);

        /// <summary>
        /// Creates a new instance of <see cref="OneTimePasswordAccount"/> from the specified <paramref name="Uri"/> using Google's de facto standard documented <a href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">here.</a>
        /// </summary>
        /// <param name="uri"></param>
        public static bool TryParse(string uri, out AuthenticatorAccount account)
        {
            try
            {
                account = Parse(new Uri(uri));
                return true;
            }
            catch (Exception)
            {
                account = null;
                return false;
            }
        }

        /// <summary>
        /// Creates a new instance of <see cref="OneTimePasswordAccount"/> from the specified <paramref name="Uri"/> using Google's de facto standard documented <a href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">here.</a>
        /// </summary>
        /// <param name="uri"></param>
        public static bool TryParse(Uri uri, out AuthenticatorAccount account)
        {
            try
            {
                account = Parse(uri);
                return true;
            }
            catch (Exception)
            {
                account = null;
                return false;
            }
        }

        public static AuthenticatorAccount Parse(string uri) => Parse(new Uri(uri));

        public static AuthenticatorAccount Parse(Uri uri)
        {
            if (uri == null) throw new ArgumentNullException(nameof(uri));
            if (!uri.Scheme.Equals("otpauth", StringComparison.OrdinalIgnoreCase) || uri.Segments.Length < 2 || !uri.Segments[0].Equals("/")) throw new FormatException("Uri does not follow Google Authenticator format.");
            if(!Enum.TryParse<AuthenticatorType>(uri.Host, true, out AuthenticatorType authenticatorType))
            {
                throw new FormatException("Could not parse authenticator type.");
            }
            AuthenticatorAccount account;
            switch (authenticatorType)
            {
                case AuthenticatorType.HOTP:
                    {
                        account = new CounterBasedAuthenticatorAccount();
                        break;
                    }
                case AuthenticatorType.TOTP:
                    {
                        account = new TimeBasedAuthenticatorAccount();
                        break;
                    }
                case AuthenticatorType.Steam:
                    {
                        account = new SteamAccount();
                        break;
                    }
                default: throw new InvalidOperationException("Authenticator account type not recognized.");
            }
            account.AuthenticatorType = authenticatorType;

            var label = Uri.UnescapeDataString(uri.Segments[1]);
            if (label.Contains(':'))
            {
                account.Issuer = label.Substring(0, label.IndexOf(':'));
                account.Name = label.Substring(label.IndexOf(':') + 1).Trim(); // Key Uri Format allows for an optional space after the colon
            }
            else
            {
                account.Name = label;
            }

            foreach (var query in uri.Query.Substring(1).Split('&'))
            {
                var queryPair = query.Split('=');
                var key = Uri.UnescapeDataString(queryPair[0]);
                var value = Uri.UnescapeDataString(queryPair[1]);

                switch (key.ToLowerInvariant())
                {
                    case "algorithm":
                        {
                            if (string.Equals(value, "SHA2", StringComparison.InvariantCultureIgnoreCase)) value = "SHA256";
                            switch (value)
                            {
                                case "SHA1":
                                case "SHA256":
                                case "SHA384":
                                case "SHA512": break;
                                default: throw new FormatException("Unable to parse the algorithm name.");
                            }
                            account.HashAlgorithm = new HashAlgorithmName(value.ToUpperInvariant());
                            break;
                        }

                    case "digits":
                        {
                            try
                            {
                                var passwordLength = uint.Parse(value);
                                if(passwordLength < CounterBasedAuthenticator.RFC_MINIMUM_PASSWORD_LENGTH || passwordLength > CounterBasedAuthenticator.RFC_MAXIMUM_PASSWORD_LENGTH)
                                {
                                    throw new FormatException("Password length must be between or equal to 6 and 9.");
                                }
                                account.PasswordLength = passwordLength;
                            }
                            catch(Exception ex)
                            {
                                throw new FormatException("Could not parse password length.", ex);
                            }
                            break;
                        }

                    case "secret": account.Secret = Base32Encoding.GetBytes(value); break;

                    case "issuer": account.Issuer = Uri.UnescapeDataString(value); break;

                    case "counter":
                        {
                            if (account is CounterBasedAuthenticatorAccount)
                            {
                                (account as CounterBasedAuthenticatorAccount).Counter = BitConverter.GetBytes(long.Parse(value));
                            }
                            else
                            {
                                throw new FormatException("A valid counter value was provided for a non counter based account.");
                            }
                            break;
                        }

                    case "period":
                        {
                            if (account is TimeBasedAuthenticatorAccount)
                            {
                                (account as TimeBasedAuthenticatorAccount).Period = TimeSpan.FromSeconds(long.Parse(value));
                            }
                            else
                            {
                                throw new FormatException("A valid time period value was provider for a non time based account.");
                            }
                            break;
                        }
                }
            }
            return account;
        }

    }
}
