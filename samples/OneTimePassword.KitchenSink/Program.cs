﻿using System;
using OneTimePassword;
using OneTimePassword.AuthenticatorAccounts;

namespace OneTimePassword.KitchenSink
{
    static class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(new TimeBasedAuthenticatorAccount() { Name = "OneTimePassword" });
            Console.WriteLine(new CounterBasedAuthenticatorAccount() { Name = "OneTimePassword" });
            Console.WriteLine(new SteamAccount() { Name = "OneTimePassword"});

        }
    }
}
