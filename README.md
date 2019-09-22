# OneTimePassword ![Nuget (with prereleases)](https://img.shields.io/nuget/vpre/OneTimePassword)

RFC 4226 (HOTP) and RFC 6238 (TOTP) implementation for .NET, also supports parsing [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) for Google Authenticator Uris and Steam's custom TOTP implementation.

**This library does not include server side validation logic, however you can implement your own logic using this library according to your security requirements.**

# Installation

```Install-Package OneTimePassword```

# Usage examples


## From Uri

``` csharp
AuthenticatorAccount.TryParse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30", out var account); 
var password = account.GeneratePassword().Password;
```
## From custom parameters

``` csharp
using (var hmac = HMAC.Create("HMACSHA1"))
{
    var length = 6;
    var time = DateTimeOffset.Now;
    var period = TimeSpan.FromSeconds(30);
    var secret = Encoding.ASCII.GetBytes("12345678901234567890");
    var password = new TimeBasedAuthenticator().GeneratePassword(length, hmac, secret, time, period).Password;
}

```

# License

Copyright 2019 Prajay Basu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
