//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OneTimePassword
{
	public class OneTimePassword
	{
        /// <summary>
        /// The time until which the one time password can be used.
        /// </summary>
        public DateTimeOffset? ValidUntil { get; internal set; } = null;

		/// <summary>
		/// The generated password.
		/// </summary>
		public string Password { get; internal set; }

        /// <summary>
        /// The last counter value used to generate a password
        /// </summary>
        public byte[] LastCounter { get; internal set; }

        /// <summary>
        /// Initializes an instance of <see cref="OneTimePassword"/> with the specific parameters.
        /// </summary>
        /// <param name="password">The generated password</param>
        /// <param name="validUntil">The Time until which it will be valid</param>
        public OneTimePassword(string password, DateTimeOffset? validUntil = null)
		{
			Password = password;
			ValidUntil = validUntil;
		}

        /// <summary>
        /// Initializes an instance of <see cref="OneTimePassword"/> with the specific parameters.
        /// </summary>
        /// <param name="password">The generated password</param>
        /// <param name="lastCounter">The counter value used for generating the HOTP value. </param>
        public OneTimePassword(string password, byte[] lastCounter)
        {
            Password = password;
            LastCounter = lastCounter;
        }
    }
}
