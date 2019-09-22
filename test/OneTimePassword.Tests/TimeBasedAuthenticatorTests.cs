//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using Xunit;
using System.Security.Cryptography;
using System.Text;
using OneTimePassword.Authenticators;

namespace OneTimePassword.Tests
{
    
    /// <summary>
    /// Test vectors taken from https://tools.ietf.org/id/draft-mraihi-totp-timebased-06.html#Section-Test-Vectors
    /// </summary>
    public static class TimeBasedAuthenticatorTests
    {
        const string RfcSecretSha1 = "12345678901234567890";
        const string RfcSecretSha256 = "12345678901234567890123456789012";
        const string RfcSecretSha512 = "1234567890123456789012345678901234567890123456789012345678901234";

        //         Algorithm|     Secret     |  Timestamp | Expected  OTP
        [InlineData(  "SHA1",   RfcSecretSha1,          59, "94287082")]
        [InlineData("SHA256", RfcSecretSha256,          59, "46119246")]
        [InlineData("SHA512", RfcSecretSha512,          59, "90693936")]
        [InlineData(  "SHA1",   RfcSecretSha1,  1111111109, "07081804")]
        [InlineData("SHA256", RfcSecretSha256,  1111111109, "68084774")]
        [InlineData("SHA512", RfcSecretSha512,  1111111109, "25091201")]
        [InlineData(  "SHA1",   RfcSecretSha1,  1111111111, "14050471")]
        [InlineData("SHA256", RfcSecretSha256,  1111111111, "67062674")]
        [InlineData("SHA512", RfcSecretSha512,  1111111111, "99943326")]
        [InlineData(  "SHA1",   RfcSecretSha1,  1234567890, "89005924")]
        [InlineData("SHA256", RfcSecretSha256,  1234567890, "91819424")]
        [InlineData("SHA512", RfcSecretSha512,  1234567890, "93441116")]
        [InlineData(  "SHA1",   RfcSecretSha1,  2000000000, "69279037")]
        [InlineData("SHA256", RfcSecretSha256,  2000000000, "90698825")]
        [InlineData("SHA512", RfcSecretSha512,  2000000000, "38618901")]
        [InlineData(  "SHA1",   RfcSecretSha1, 20000000000, "65353130")]
        [InlineData("SHA256", RfcSecretSha256, 20000000000, "77737706")]
        [InlineData("SHA512", RfcSecretSha512, 20000000000, "47863826")]
        [Theory]
        public static void RfcTestVectors(string hashAlgorithmName, string secret, long timestamp, string expectedResult)
        {
            using (var hmac = HMAC.Create("HMAC" + hashAlgorithmName.ToUpperInvariant()))
            {
                Assert.Equal(expectedResult, new TimeBasedAuthenticator().GeneratePassword(8, hmac, Encoding.ASCII.GetBytes(secret), DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromSeconds(30)));
            }
        }
    }
}
