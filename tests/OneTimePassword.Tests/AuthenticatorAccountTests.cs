using OneTimePassword.AuthenticatorAccounts;
using OneTimePassword.Authenticators;
using OneTimePassword.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace OneTimePassword.Tests
{
    public static class AuthenticatorAccountTests
    {
        private static readonly byte[] DefaultCounterValue = BitConverter.GetBytes(0UL);
        private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA1;

        private static readonly byte[] ValidSecretBinary = Base32Encoding.GetBytes(ValidSecretBase32);
        private const string ValidSecretBase32 = "CQAHUXJ2VWDI7WFF";
        private const string ValidAccountName = "9.99.99.999";
        private const string ValidUriScheme = "otpauth";
        private const string ValidUriHostTotp = "totp";
        private const string ValidUriHostHotp = "hotp";
        private static readonly byte[] ValidCounterValue = BitConverter.GetBytes(264UL);

        [Fact]
        public static void ParseValidTotpUri()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostTotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}"
            };
            AuthenticatorAccount.TryParse(builder.Uri, out var account);

            Assert.Equal(AuthenticatorType.TOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
        }

        [Fact]
        public static void ParseValidHotpUriWithoutCounter()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostHotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}"
            };
            AuthenticatorAccount.TryParse(builder.Uri, out var account);

            Assert.Equal(AuthenticatorType.HOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
            Assert.Equal(DefaultCounterValue, (account as CounterBasedAuthenticatorAccount).Counter);
        }

        [Fact]
        public static void ParseValidHotpUriWithValidCounter()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostHotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}&counter={BitConverter.ToInt64(ValidCounterValue)}"
            };
            AuthenticatorAccount.TryParse(builder.Uri, out var account);

            Assert.Equal(AuthenticatorType.HOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
            Assert.Equal(ValidCounterValue, (account as CounterBasedAuthenticatorAccount).Counter);
        }

        internal static void AssertValidUri(Uri uri)
        {
            var queries = uri.Query.Substring(1).Split('&');
            Assert.Equal("otpauth", uri.Scheme);
            Assert.True(uri.Host == "hotp" || uri.Host == "totp");
            Assert.Contains("secret=", uri.Query);
            if(uri.Host == "hotp")
            {
                Assert.True(!String.IsNullOrWhiteSpace(queries.Single(x => x.Contains("counter")).Split('=')[1]));
            }
        }
    }
}
