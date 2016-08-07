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
        [Fact]
        public static void TestVector1()
        {
            Assert.Equal("755224", CounterBasedAuthenticator.GeneratePassword(0, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector2()
        {
            Assert.Equal("287082", CounterBasedAuthenticator.GeneratePassword(1, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector3()
        {
            Assert.Equal("359152", CounterBasedAuthenticator.GeneratePassword(2, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector4()
        {
            Assert.Equal("969429", CounterBasedAuthenticator.GeneratePassword(3, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector5()
        {
            Assert.Equal("338314", CounterBasedAuthenticator.GeneratePassword(4, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector6()
        {
            Assert.Equal("254676", CounterBasedAuthenticator.GeneratePassword(5, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector7()
        {
            Assert.Equal("287922", CounterBasedAuthenticator.GeneratePassword(6, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector8()
        {
            Assert.Equal("162583", CounterBasedAuthenticator.GeneratePassword(7, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector9()
        {
            Assert.Equal("399871", CounterBasedAuthenticator.GeneratePassword(8, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }
        [Fact]
        public static void TestVector10()
        {
            Assert.Equal("520489", CounterBasedAuthenticator.GeneratePassword(9, 6, new HMACSHA1(), Encoding.ASCII.GetBytes("12345678901234567890")));
        }

    }
}
