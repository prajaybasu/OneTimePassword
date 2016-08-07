//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public static class Extensions
    {
        internal static HMAC GetHmac(this HashAlgorithmName name)
        {
            if (name == HashAlgorithmName.MD5)
            {
                return new HMACMD5();
            }
            else if (name == HashAlgorithmName.SHA1)
            {
                return new HMACSHA1();
            }
            else if (name == HashAlgorithmName.SHA256)
            {
                return new HMACSHA256();
            }
            else if (name == HashAlgorithmName.SHA384)
            {
                return new HMACSHA384();
            }
            else if(name == HashAlgorithmName.SHA512)
            {
                return new HMACSHA512();
            }
            else throw new InvalidOperationException("Invalid Algorithm");
        }
    }
}
