//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
namespace OneTimePassword.Tests
{
    public class Base32Tests
    {
        [Fact]
        public void ToBase32_10_bytes_1()
        {
            Assert.Equal("32W3532IMVWGY3ZB", Base32Encoding.ToBase32(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }));
        }

        [Fact]
        public void ToBase32_10_bytes_2()
        {
            Assert.Equal("JBSWY3DPEHPK3PXP", Base32Encoding.ToBase32(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }));
        }

        [Fact]
        public void ToBase32_9_bytes_1()
        {
            Assert.Equal("VW7O6SDFNRWG6II=", Base32Encoding.ToBase32(new byte[] { 0xAD, 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }));
        }

        [Fact]
        public void ToBase32_9_bytes_2()
        {
            Assert.Equal("MVWGY3ZB32W353Y=", Base32Encoding.ToBase32(new byte[] { 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }));
        }

        [Fact]
        public void ToBase32_8_bytes_1()
        {
            Assert.Equal("X3XUQZLMNRXSC===", Base32Encoding.ToBase32(new byte[] { 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }));
        }

        [Fact]
        public void ToBase32_8_bytes_2()
        {
            Assert.Equal("NRWG6IO6VW7O6===", Base32Encoding.ToBase32(new byte[] { 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }));
        }

        [Fact]
        public void ToBase32_7_bytes_1()
        {
            Assert.Equal("55EGK3DMN4QQ====", Base32Encoding.ToBase32(new byte[] { 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }));
        }

        [Fact]
        public void ToBase32_7_bytes_2()
        {
            Assert.Equal("NRXSDXVNX3XQ====", Base32Encoding.ToBase32(new byte[] { 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }));
        }

        [Fact]
        public void ToBase32_6_bytes_1()
        {
            Assert.Equal("JBSWY3DPEE======", Base32Encoding.ToBase32(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }));
        }

        [Fact]
        public void ToBase32_6_bytes_2()
        {
            Assert.Equal("N4Q55LN654======", Base32Encoding.ToBase32(new byte[] { 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }));
        }

        [Fact]
        public void ToBinary_10_bytes_1()
        {
            Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }, Base32Encoding.ToBinary("32W3532IMVWGY3ZB"));
        }

        [Fact]
        public void ToBinary_10_bytes_2()
        {
            Assert.Equal(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }, Base32Encoding.ToBinary("JBSWY3DPEHPK3PXP"));
        }

        [Fact]
        public void ToBinary_9_bytes_1()
        {
            Assert.Equal(new byte[] { 0xAD, 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }, Base32Encoding.ToBinary("VW7O6SDFNRWG6II="));
        }

        [Fact]
        public void ToBinary_9_bytes_2()
        {
            Assert.Equal(new byte[] { 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }, Base32Encoding.ToBinary("MVWGY3ZB32W353Y="));
        }

        [Fact]
        public void ToBinary_8_bytes_1()
        {
            Assert.Equal(new byte[] { 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21}, Base32Encoding.ToBinary("X3XUQZLMNRXSC==="));
        }

        [Fact]
        public void ToBinary_8_bytes_2()
        {
            Assert.Equal(new byte[] { 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }, Base32Encoding.ToBinary("NRWG6IO6VW7O6==="));
        }

        [Fact]
        public void ToBinary_7_bytes_1()
        {
            Assert.Equal(new byte[] { 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }, Base32Encoding.ToBinary("55EGK3DMN4QQ===="));
        }

        [Fact]
        public void ToBinary_7_bytes_2()
        {
            Assert.Equal(new byte[] { 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }, Base32Encoding.ToBinary("NRXSDXVNX3XQ===="));
        }

        [Fact]
        public void ToBinary_6_bytes_1()
        {
            Assert.Equal(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 }, Base32Encoding.ToBinary("JBSWY3DPEE======"));
        }

        [Fact]
        public void ToBinary_6_bytes_2()
        {
            Assert.Equal(new byte[] { 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }, Base32Encoding.ToBinary("N4Q55LN654======"));
        }
    }
}
