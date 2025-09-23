//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//
using System.Security.Cryptography;

namespace Deephaven.Dhe_NetClient;

public abstract class Credentials {
  /// <summary>
  /// Generates a PasswordCredentials with the specified fields.
  /// </summary>
  /// <returns><see cref="Credentials"/> for use with username/password</returns>
  public static Credentials OfUsernamePassword(string user, string password, string operateAs) {
    return new PasswordCredentials(user, password, operateAs);
  }

  /// <summary>
  /// Generates a SamlCredentials with a new, crytprographically-random nonce.
  /// </summary>
  /// <returns><see cref="Credentials"/> for use with SAML</returns>
  public static Credentials OfSaml(string nonce) {
    return new SamlCredentials(nonce);
  }

  /// <summary>
  /// Generates a new, crytprographically-random nonce for use with OfSaml
  /// </summary>
  /// <returns>The nonce</returns>
  public static string GenerateRandomNonceForSaml() {
    var bytes = new byte[96];
    RandomNumberGenerator.Fill(bytes);
    var nonce = Convert.ToBase64String(bytes);
    return nonce;
  }

  internal class PasswordCredentials(string user, string password,
    string operateAs) : Credentials {
    public readonly string User = user;
    public readonly string Password = password;
    public readonly string OperateAs = operateAs;
  }

  internal class SamlCredentials(string nonce) : Credentials {
    public readonly string Nonce = nonce;
  }
}
