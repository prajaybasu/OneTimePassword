//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using OneTimePassword.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
namespace OneTimePassword.Tests
{
    public class Base32Tests
    {
        //Test vectors taken from https://tools.ietf.org/html/rfc4648

        [InlineData("", "")]
        [InlineData("MY======", "f")]
        [InlineData("MZXQ====", "fo")]
        [InlineData("MZXW6===", "foo")]
        [InlineData("MZXW6YQ=", "foob")]
        [InlineData("MZXW6YTB", "fooba")]
        [InlineData("MZXW6YTBOI======", "foobar")]
        [Theory]
        public static void RfcTestVectors(string base32, string ascii)
        {
            Assert.Equal(base32, Base32Encoding.GetString(Encoding.ASCII.GetBytes(ascii)));
            Assert.Equal(Base32Encoding.GetBytes(base32), Encoding.ASCII.GetBytes(ascii));
        }

        //Test vectors taken from https://github.com/jennings/OATH.Net/blob/master/OATH.Net.Test/Base32Tests.cs

        [InlineData("32W3532IMVWGY3ZB", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 })]
        [InlineData("JBSWY3DPEHPK3PXP", new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF })]
        [InlineData("VW7O6SDFNRWG6II=", new byte[] { 0xAD, 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 })]
        [InlineData("MVWGY3ZB32W353Y=", new byte[] { 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF })]
        [InlineData("X3XUQZLMNRXSC===", new byte[] { 0xBE, 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 })]
        [InlineData("NRWG6IO6VW7O6===", new byte[] { 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF })]
        [InlineData("55EGK3DMN4QQ====", new byte[] { 0xEF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 })]
        [InlineData("NRXSDXVNX3XQ====", new byte[] { 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF })]
        [InlineData("JBSWY3DPEE======", new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21 })]
        [InlineData("N4Q55LN654======", new byte[] { 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF })]
        [Theory]
        public static void OathNetTestVectors(string base32, byte[] bytes)
        {
            Assert.Equal(base32, Base32Encoding.GetString(bytes));
            Assert.Equal(bytes, Base32Encoding.GetBytes(base32));
        }

        [Fact]
        public void GetBytes_WithInvalidChars_ThrowsFormatException()
        {
            var invalidChars = new List<string>()
            {
                "1", "8", "9", "0",
                "`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+",
                "[", "]", "{", "}", "|", "\\",
                ";", ":", "'", "\"",
                ",", ".", "<", ">", "/", "?"
            };

            foreach (var s in invalidChars)
            {
                Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("ABCD" + s + "EFG"));
            }
        }

        [Fact]
        public void GetBytes_WithSingleChar_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("M"));
        }

        [Fact]
        public void GetBytes_WithPlainPadding_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("========"));
        }

        [Fact]
        public void GetBytes_WithIncompletePadding()
        {
            Assert.Equal(Encoding.ASCII.GetBytes("foobar"), Base32Encoding.GetBytes("MZXW6YTBOI====="));
        }

        [Fact]
        public void GetBytes_WithPaddingInsideText_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("MZX=6YQ="));
        }

        [Fact]
        public void GetBytes_WithInvalidCharInAlphabet_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("MZX96YQ="));
        }

        [Fact]
        public void GetBytes_WithInvalidCharNotInAlphabet_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("MZX$6YQ="));
        }

        [Fact]
        public void GetBytes_WithInvalidCharNotInAlphabetRight_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => Base32Encoding.GetBytes("MZX~6YQ="));
        }

        const string Complex1Text = "The Base 32 encoding is designed to represent arbitrary " +
                                            "sequences of octets in a form that needs to be case insensitive " +
                                            "but that need not be human readable.";

        const string Complex1Base32 = "KRUGKICCMFZWKIBTGIQGK3TDN5SGS3THEBUXGIDEMVZWSZ3OMVSCA5DP" +
                                              "EBZGK4DSMVZWK3TUEBQXEYTJORZGC4TZEBZWK4LVMVXGGZLTEBXWMIDP" +
                                              "MN2GK5DTEBUW4IDBEBTG64TNEB2GQYLUEBXGKZLEOMQHI3ZAMJSSAY3B" +
                                              "ONSSA2LOONSW443JORUXMZJAMJ2XIIDUNBQXIIDOMVSWIIDON52CAYTF" +
                                              "EBUHK3LBNYQHEZLBMRQWE3DFFY======";

        [Fact]
        public void GetBytes_WithComplexString()
        {
            Assert.Equal(Complex1Base32, Base32Encoding.GetString(Encoding.ASCII.GetBytes(Complex1Text)));
            Assert.Equal(Encoding.ASCII.GetBytes(Complex1Text), Base32Encoding.GetBytes(Complex1Base32));
        }


    }
}
