using System;
using Xunit;
using OneTimePassword;
using System.Security.Cryptography;
using System.Text;

namespace OneTimePassword.Tests
{
    /// <summary>
    /// Test vectors taken from https://tools.ietf.org/id/draft-mraihi-totp-timebased-06.html#Section-Test-Vectors
    /// </summary>
    public class TimeAuthenticatorTests
    {
        [Fact]
        public static void TestVector1()
        {
            Assert.Equal("94287082", TimeBasedAuthenticator.GeneratePassword(8,new HMACSHA1(),ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector2()
        {
            Assert.Equal("32247374", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector3()
        {
            Assert.Equal("69342147", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector4()
        {
            Assert.Equal("07081804", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA1(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector5()
        {
            Assert.Equal("34756375", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector6()
        {
            Assert.Equal("63049338", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector7()
        {
            Assert.Equal("14050471", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA1(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector8()
        {
            Assert.Equal("74584430", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector9()
        {
            Assert.Equal("54380122", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector10()
        {
            Assert.Equal("89005924", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA1(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector11()
        {
            Assert.Equal("42829826", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector12()
        {
            Assert.Equal("76671578", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector13()
        {
            Assert.Equal("69279037", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA1(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector14()
        {
            Assert.Equal("78428693", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector15()
        {
            Assert.Equal("56464532", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector16()
        {
            Assert.Equal("46119246", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012"), new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector17()
        {
            Assert.Equal("90693936", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"), new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector18()
        {
            Assert.Equal("68084774", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012"), new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector19()
        {
            Assert.Equal("25091201", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"), new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector20()
        {
            Assert.Equal("67062674", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012"), new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector21()
        {
            Assert.Equal("99943326", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"), new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector22()
        {
            Assert.Equal("91819424", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012"), new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector23()
        {
            Assert.Equal("93441116", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"), new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector24()
        {
            Assert.Equal("90698825", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012"), new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector25()
        {
            Assert.Equal("38618901", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"), new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector26()
        {
            Assert.Equal("65353130", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA1(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890"), new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector27()
        {
            Assert.Equal("77737706", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA256(), ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012"), new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
        [Fact]
        public static void TestVector28()
        {
            Assert.Equal("47863826", TimeBasedAuthenticator.GeneratePassword(8, new HMACSHA512(), ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"), new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc), TimeSpan.FromSeconds(30)));
        }
    }
}
