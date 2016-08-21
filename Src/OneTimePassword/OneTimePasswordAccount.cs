//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Runtime.Serialization;
using System.Diagnostics.Contracts;

namespace OneTimePassword
{
	//https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	public class OneTimePasswordAccount
	{
		#region Properties
		/// <summary>
		/// Type of Authenticator.
		/// <seealso cref="AuthenticatorType"/>
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), JsonProperty(PropertyName = "type")]
		public AuthenticatorType Type { get; set; } = AuthenticatorType.TOTP;
		/// <summary>
		/// The name of the account.
		/// </summary>
		[JsonProperty(PropertyName = "label", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public string Label { get; set; }
		/// <summary>
		/// Optional. The name of the organization or company the account belongs to.
		/// </summary>
		[JsonProperty(PropertyName = "issuer", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public string Issuer { get; set; }
		/// <summary>
		/// The raw bytes for the account secret used to generate OTP codes.
		/// </summary>
		[JsonProperty(PropertyName = "secret", DefaultValueHandling = DefaultValueHandling.Include)]
		public byte[] Secret { get; set; }
		/// <summary>
		/// It will set the initial counter value when provisioning a key for use with HOTP
		/// </summary>
		[JsonProperty(PropertyName = "counter",DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public long Counter { get; set; } = 0;

		/// <summary>
		/// It defines the validity of the OTP issued.
		/// </summary>
		[JsonProperty(PropertyName = "period", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public TimeSpan Period { get; set; } = TimeSpan.FromSeconds(30);

		/// <summary>
		///  The algorithm to be used when generating the one time password.
		///  <seealso cref="HashAlgorithmName"/>
		/// </summary>
		[JsonProperty(PropertyName = "algorithm", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public HashAlgorithmName Algorithm { get; set; } = HashAlgorithmName.SHA1;

		/// <summary>
		/// The length of the password.
		/// </summary>
		[JsonProperty(PropertyName = "digits", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public int PasswordLength { get; set; } = 6;

		/// <summary>
		/// Stores the metadata for the account.
		/// </summary>
		[JsonProperty(PropertyName ="metadata", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
		public Dictionary<string,string> Metadata { get; set; }
		#endregion

		#region Methods
		/// <summary>
		/// Generates a one time password using the given parameters.
		/// </summary>
		public OneTimePassword GeneratePassword() => this.GetAuthenticator().GeneratePassword(this);
		#endregion

		#region Constructors
		/// <summary>
		/// Creates a new instance of <see cref="OneTimePasswordAccount"/> using the default options.
		/// </summary>
		public OneTimePasswordAccount() { }
		/// <summary>
		/// Creates a new instance of <see cref="OneTimePasswordAccount"/> from the specified <paramref name="Uri"/> using Google's de facto standard documented <a href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">here.</a>
		/// </summary>
		/// <param name="uri"></param>
		public OneTimePasswordAccount(Uri uri,bool setDefaults = true)
		{
			if (uri.Segments.Length < 2) throw new ArgumentOutOfRangeException(nameof(uri), "Invalid Uri.");
			if (!uri.Scheme.Equals("otpauth", StringComparison.OrdinalIgnoreCase)) throw new ArgumentOutOfRangeException(nameof(uri), "Invalid Uri.");
			if (uri == null) throw new ArgumentNullException(nameof(uri), "Uri cannot be null.");
			Contract.EndContractBlock();
			try
			{
				Type = (AuthenticatorType)Enum.Parse(typeof(AuthenticatorType), uri.Authority, true);
			}
			catch(Exception ex)
			{
				if (!setDefaults)
				{
					throw new InvalidOperationException("Authenticator not supported", ex);
				}
			}
			Label = Uri.UnescapeDataString(uri.Segments[1]);
			if(Label.Contains(':'))
			{
				Issuer = Label.Substring(0, Label.IndexOf(':'));
				Label = Label.Substring(Label.IndexOf(':') + 1);
			}
			var queries = uri.Query.Substring(1).Split('&');
			foreach (var query in queries)
			{
				var queryPair = query.Split('=');
				var key = Uri.UnescapeDataString(queryPair[0]);
				var value = Uri.UnescapeDataString(queryPair[1]);
				if(key.Equals("algorithm",StringComparison.OrdinalIgnoreCase))
				{
					try
					{
						Algorithm = new HashAlgorithmName(value.ToUpperInvariant());
					}
					catch(Exception ex)
					{
						throw new InvalidOperationException("Algorithm is not supported", ex);
					}
				}
				else if(key.Equals("digits", StringComparison.OrdinalIgnoreCase))
				{
					try
					{
						PasswordLength = Int32.Parse(value);
					}
					catch (Exception ex)
					{
						throw new InvalidOperationException("Password Length is invalid", ex);
					}
				} 
				else if(key.Equals("counter", StringComparison.OrdinalIgnoreCase))
				{
					try
					{
						Counter = Int64.Parse(value);
					}
					catch(Exception ex)
					{
						throw new InvalidOperationException("Count is invalid", ex);
					}
				}
				else if(key.Equals("period", StringComparison.OrdinalIgnoreCase) || key.Equals("interval", StringComparison.OrdinalIgnoreCase))
				{
					try
					{
						Period = TimeSpan.FromSeconds(Double.Parse(value));
					}
					catch (Exception ex)
					{
						throw new InvalidOperationException("Period is invalid", ex);
					}
				}
				else if(key.Equals("secret", StringComparison.OrdinalIgnoreCase))
				{
					try
					{
						Secret = Base32Encoding.ToBinary(value);
					}
					catch (Exception ex)
					{
						throw new InvalidOperationException("Secret is invalid", ex);
					}
				}
				else if(key.Equals("issuer", StringComparison.OrdinalIgnoreCase))
				{
					Issuer = value;
				}
			}
		}
		#endregion
	}
	public enum AuthenticatorType
	{
		[EnumMember(Value = "hotp")]
		HOTP,

		[EnumMember(Value = "totp")]
		TOTP
	}
}
