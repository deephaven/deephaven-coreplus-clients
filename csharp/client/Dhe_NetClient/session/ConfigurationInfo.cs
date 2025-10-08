using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;

namespace Deephaven.Dhe_NetClient;

public sealed class ConfigurationInfo {
  [JsonPropertyName("auth_host")]
  public required string[] AuthHost { get; init; }
  [JsonPropertyName("auth_port")]
  public required UInt16 AuthPort { get; init; }
  [JsonPropertyName("controller_host")]
  public required string ControllerHost { get; init; }
  [JsonPropertyName("controller_port")]
  public required UInt16 ControllerPort { get; init; }
  [JsonPropertyName("truststore_url")]
  public string? TruststoreUrl { get; init; }
  [JsonPropertyName("override_authorities")]
  public bool OverrideAuthorities { get; init; }
  [JsonPropertyName("auth_authority")]
  public string? AuthAuthority { get; init; }
  [JsonPropertyName("controller_authority")]
  public string? ControllerAuthority { get; init; }
  [JsonPropertyName("saml_sso_uri")]
  public string? SamlSsoUri { get; init; }

  public static ConfigurationInfo OfJson(string input) {
    var result = JsonSerializer.Deserialize<ConfigurationInfo>(input);
    return result ?? throw new Exception("JsonSerializer returned null");
  }

  public static ConfigurationInfo OfUri(Uri uri, bool validateCertificate) {
    var handler = new HttpClientHandler();
    if (!validateCertificate) {
      handler.ClientCertificateOptions = ClientCertificateOption.Manual;
      handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
    }
    using var hc = new HttpClient(handler);
    var json = hc.GetStringAsync(uri).Result;

    return OfJson(json);
  }

  public Uri MakeSamlAuthUri(string nonce) {
    return TryMakeSamlAuthUri(nonce, out var uri, out var errorText) ?
      uri :
      throw new Exception(errorText);
  }

  public bool TryMakeSamlAuthUri(string nonce,
    [MaybeNullWhen(false)] out Uri uri,
    [MaybeNullWhen(true)] out string errorText) {
    uri = null;
    errorText = null;

    if (SamlSsoUri == null) {
      errorText = "Server not configured for SAML";
      return false;
    }

    try {
      var uriBuilder = new UriBuilder(SamlSsoUri);
      var query = HttpUtility.ParseQueryString(uriBuilder.Query);
      query["key"] = nonce;
      uriBuilder.Query = query.ToString();
      uri = uriBuilder.Uri;
      return true;
    } catch (Exception e) {
      errorText = $"Malformed SAML URI from configuration: {e.Message}";
      return false;
    }
  }
}
