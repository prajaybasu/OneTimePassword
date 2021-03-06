﻿//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using Xunit;
using System.Security.Cryptography;
using System.Text;
using OneTimePassword.Authenticators;
using System;

namespace OneTimePassword.Tests
{
    public static class CounterBasedAuthenticatorTests
    {
        private const string RfcSecretSha1 = "12345678901234567890";
        //       Algorithm|    Secret    |Counter|Expected OTP
        [InlineData("SHA1", RfcSecretSha1,      0, "755224")]
        [InlineData("SHA1", RfcSecretSha1,      1, "287082")]
        [InlineData("SHA1", RfcSecretSha1,      2, "359152")]
        [InlineData("SHA1", RfcSecretSha1,      3, "969429")]
        [InlineData("SHA1", RfcSecretSha1,      4, "338314")]
        [InlineData("SHA1", RfcSecretSha1,      5, "254676")]
        [InlineData("SHA1", RfcSecretSha1,      6, "287922")]
        [InlineData("SHA1", RfcSecretSha1,      7, "162583")]
        [InlineData("SHA1", RfcSecretSha1,      8, "399871")]
        [InlineData("SHA1", RfcSecretSha1,      9, "520489")]
        [Theory]
        public static void RfcTestVectors(string hashAlgorithmName, string secret, ulong counter, string expectedResult)
        {
            using (var hmac = HMAC.Create("HMAC" + hashAlgorithmName.ToUpperInvariant()))
            {
                Assert.Equal(expectedResult, new CounterBasedAuthenticator().GeneratePassword(hmac, Encoding.ASCII.GetBytes(secret), BitConverter.GetBytes(counter)));
            }
        }

        [Fact]
        public static void GeneratePassword_WithInvalidLength_ThrowsArgumentOutOfRangeException()
        {
            const ulong counter = 0UL;
            const uint length = 5U;
            using (var hmac = HMAC.Create("HMACSHA1"))
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new CounterBasedAuthenticator().GeneratePassword(hmac, Encoding.ASCII.GetBytes(RfcSecretSha1), BitConverter.GetBytes(counter), length));
            }
        }
    }
}
