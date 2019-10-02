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

            Assert.Equal("otpauth://totp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF", builder.Uri.ToString());
            AuthenticatorAccount.TryParse(builder.Uri, out var account);

            Assert.Equal(AuthenticatorType.TOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
        }

        [Fact]
        public static void ParseValidTotpUriWithSha2Algorithm()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostTotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}&algorithm=sha2"
            };

            Assert.Equal("otpauth://totp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF&algorithm=sha2", builder.Uri.ToString());
            var account = AuthenticatorAccount.Parse(builder.Uri);

            Assert.Equal(AuthenticatorType.TOTP, account.AuthenticatorType);
            Assert.Equal(HashAlgorithmName.SHA256, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
        }

        [Fact]
        public static void ParseValidHotpUriWithSha2Algorithm()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostHotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}&algorithm=sha2"
            };

            Assert.Equal("otpauth://hotp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF&algorithm=sha2", builder.Uri.ToString());
            var account = AuthenticatorAccount.Parse(builder.Uri);

            Assert.Equal(AuthenticatorType.HOTP, account.AuthenticatorType);
            Assert.Equal(HashAlgorithmName.SHA256, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
        }

        [Fact]
        public static void ParseValidHotpUri()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostHotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}"
            };

            Assert.Equal("otpauth://hotp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF", builder.Uri.ToString());
            var account = AuthenticatorAccount.Parse(builder.Uri);

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

            Assert.Equal("otpauth://hotp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF&counter=264", builder.Uri.ToString());
            var account = AuthenticatorAccount.Parse(builder.Uri);

            Assert.Equal(AuthenticatorType.HOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal(ValidAccountName, account.Name);
            Assert.Equal(ValidSecretBinary, account.Secret);
            Assert.Equal(ValidCounterValue, (account as CounterBasedAuthenticatorAccount).Counter);
        }

        [Fact]
        public static void ParseHotpUriInvalidAlgorithmThrowsFormatException()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostHotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}&algorithm=sha9"
            };

            Assert.Equal("otpauth://hotp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF&algorithm=sha9", builder.Uri.ToString());
            Assert.Throws<FormatException>(() => AuthenticatorAccount.Parse(builder.Uri));
        }

        [Fact]
        public static void ParseTotpUriInvalidAlgorithmThrowsFormatException()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostTotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}&algorithm=sha132"
            };

            Assert.Equal("otpauth://totp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF&algorithm=sha132", builder.Uri.ToString());
            Assert.Throws<FormatException>(() => AuthenticatorAccount.Parse(builder.Uri));
        }

        [Fact]
        public static void ParseTotpUriWithShortPasswordLengthThrowsFormatException()
        {
            var builder = new UriBuilder
            {
                Scheme = ValidUriScheme,
                Host = ValidUriHostTotp,
                Path = ValidAccountName,
                Query = $"secret={ValidSecretBase32}&digits=5"
            };

            Assert.Equal("otpauth://totp/9.99.99.999?secret=CQAHUXJ2VWDI7WFF&digits=5", builder.Uri.ToString());
            Assert.Throws<FormatException>(() => AuthenticatorAccount.Parse(builder.Uri));
        }

        [Fact]
        public static void ParseValidGoogleAuthenticatorUriWithOptionalParameters()
        {
            var account = AuthenticatorAccount.Parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30");
           

            Assert.Equal(AuthenticatorType.TOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal("john.doe@email.com", account.Name);
            Assert.Equal("ACME Co", account.Issuer);
            Assert.Equal(Base32Encoding.GetBytes("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"), account.Secret);
        }


        [Fact]
        public static void ParseValidGoogleAuthenticatorUri()
        {
            byte[] secret = { (byte)'H', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)'!',
                0xDE, 0xAD, 0xBE, 0xEF };
            var account = AuthenticatorAccount.Parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");

            Assert.Equal(AuthenticatorType.TOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal("alice@google.com", account.Name);
            Assert.Equal(secret, account.Secret);
        }

        [Fact]
        public static void ParseValidTotpUriWithIgnoredParameters()
        {
            byte[] secret = { (byte)'H', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)'!',
                0xDE, 0xAD, 0xBE, 0xEF };
            var account = AuthenticatorAccount.Parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&lmirequesttoken=90_E3463hawd39zikKSgDlgcb56435645y6hrtsdfawefawerea754_23q54w432554&lmiversion=1");

            Assert.Equal(AuthenticatorType.TOTP, account.AuthenticatorType);
            Assert.Equal(DefaultHashAlgorithm, account.HashAlgorithm);
            Assert.Equal("alice@google.com", account.Name);
            Assert.Equal(secret, account.Secret);
        }

        [Fact]
        public static void ToStringTimeBasedAuthenticatorAccount()
        {
            var uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
            var account = new TimeBasedAuthenticatorAccount()
            {
                Secret = Base32Encoding.GetBytes("JBSWY3DPEHPK3PXP"),
                Issuer = "Example",
                Name = "alice@google.com"
            };
            Assert.Equal(uri, account.ToString());
        }

        [Fact]
        public static void ToStringTimeBasedAuthenticatorAccountWithSha256()
        {
            var uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&algorithm=sha2&issuer=Example";
            var account = new TimeBasedAuthenticatorAccount()
            {
                Secret = Base32Encoding.GetBytes("JBSWY3DPEHPK3PXP"),
                Issuer = "Example",
                Name = "alice@google.com",
                HashAlgorithm = HashAlgorithmName.SHA256
            };
            Assert.Equal(uri, account.ToString());
        }

        [Fact]
        public static void ToStringTimeBasedAuthenticatorAccountWithSha512()
        {
            var uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&algorithm=sha512&issuer=Example";
            var account = new TimeBasedAuthenticatorAccount()
            {
                Secret = Base32Encoding.GetBytes("JBSWY3DPEHPK3PXP"),
                Issuer = "Example",
                Name = "alice@google.com",
                HashAlgorithm = HashAlgorithmName.SHA512
            };
            Assert.Equal(uri, account.ToString());
        }

        [Fact]
        public static void ToStringTimeBasedAuthenticatorAccountWith60SecondPeriod()
        {
            var uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&period=60&issuer=Example";
            var account = new TimeBasedAuthenticatorAccount()
            {
                Secret = Base32Encoding.GetBytes("JBSWY3DPEHPK3PXP"),
                Issuer = "Example",
                Name = "alice@google.com",
                Period = TimeSpan.FromSeconds(60)
            };
            Assert.Equal(uri, account.ToString());
        }

        internal static void AssertValidUri(Uri uri)
        {
            var queries = uri.Query.Substring(1).Split('&');
            Assert.Equal("otpauth", uri.Scheme);
            Assert.True(uri.Host == "hotp" || uri.Host == "totp");
            Assert.Contains("secret=", uri.Query);
            if(uri.Host == "hotp")
            {
                Assert.True(!string.IsNullOrWhiteSpace(queries.Single(x => x.Contains("counter")).Split('=')[1]));
            }
        }
    }
}
