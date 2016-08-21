//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using Xunit;
using System.Security.Cryptography;
using System.Text;

namespace OneTimePassword.Tests
{
    public class CounterAuthenticatorTests
    {
        static CounterBasedAuthenticator authenticator = new CounterBasedAuthenticator();
        [Fact]
        public static void TestVector1()
        {
            Assert.Equal("755224", authenticator.GeneratePassword(0, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector2()
        {
            Assert.Equal("287082", authenticator.GeneratePassword(1, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector3()
        {
            Assert.Equal("359152", authenticator.GeneratePassword(2, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector4()
        {
            Assert.Equal("969429", authenticator.GeneratePassword(3, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector5()
        {
            Assert.Equal("338314", authenticator.GeneratePassword(4, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector6()
        {
            Assert.Equal("254676", authenticator.GeneratePassword(5, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector7()
        {
            Assert.Equal("287922", authenticator.GeneratePassword(6, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector8()
        {
            Assert.Equal("162583", authenticator.GeneratePassword(7, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector9()
        {
            Assert.Equal("399871", authenticator.GeneratePassword(8, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector10()
        {
            Assert.Equal("520489", authenticator.GeneratePassword(9, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }

    }
}
