using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public static class CounterBasedAuthenticator
    {
        internal static readonly int[] digitPowers = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
        public static string GeneratePassword(long counter,int length,HMAC hmac, byte[] secret)
        {
            var text = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                text = text.Reverse().ToArray();
            hmac.Key = secret;
            var hash = hmac.ComputeHash(text);
            int offset = hash.Last() & 0xF;
            hmac.Key = new byte[] {0,0};
            var result = ((

                        ((hash[offset + 0] & 0x7f) << 24) |

                        ((hash[offset + 1] & 0xff) << 16) |

                        ((hash[offset + 2] & 0xff) << 8) |

                        (hash[offset + 3] & 0xff)

                    ) % digitPowers[length]).ToString();
            while(result.Length  < length)
            {
                result = "0" + result;
            }
            return result;
        }

    }
}
