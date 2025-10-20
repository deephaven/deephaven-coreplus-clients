//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//
using Deephaven.Dhe_NetClient;

namespace Deephaven.Dhe_NetClientTests;

public sealed class CommonContextForTests : IDisposable {
  /// <summary>
  /// We provide two options for setting the server JSON URL, user, and password when running unit tests.
  /// 1. Look for the environment variables DH_TEST_JSON_URL, DH_TEST_USER, and DH_TEST_PASSWORD.
  /// 2. If not found, use DefaultDhJsonUrl, DefaultDhUser, and DefaultDhPassword
  /// The Visual Studio test runner will read environment variable settings from the .runsettings file
  /// in the project directory. However, note that the Resharper test runner does not seem to honor
  /// .runsettings.
  /// </summary>
  private const string? DefaultDhJsonUrl = null;

  private const string? DefaultDhUser = null;

  private const string? DefaultDhPassword = null;

  public readonly SessionManager SessionManager;

  public static CommonContextForTests Create() {
    var sm = CreateSessionManager();
    return new CommonContextForTests(sm);
  }

  private CommonContextForTests(SessionManager sessionManager) {
    SessionManager = sessionManager;
  }

  public void Dispose() {
    SessionManager.Dispose();
  }

  private static SessionManager CreateSessionManager() {
    var missing = new List<string>();
    var jsonUrl = TryGetEnv("DH_TEST_JSON_URL", DefaultDhJsonUrl, missing);
    var user = TryGetEnv("DH_TEST_USER", DefaultDhUser, missing);
    var password = TryGetEnv("DH_TEST_PASSWORD", DefaultDhPassword, missing);

    if (missing.Count != 0) {
      throw new Exception($"The following environment variables were not found: {string.Join(", ", missing)}.\n" +
        "Please set them in your environment.\n" +
        "Sample values:\n" +
        "  DH_HOST=https://myserver.myorganization:8123/iris/connection.json\n" +
        "  DH_TEST_USER=myname\n" +
        "  DH_TEST_PASSWORD=hunter2\n" +
        "If using the Visual Studio test runner you can edit the .runsettings file in the project directory.\n" +
        "However please note that if you are using the *ReSharper* test runner it will not honor .runsettings\n" +
        $"Otherwise you can edit {nameof(CommonContextForTests)}.{nameof(DefaultDhJsonUrl)}, " +
        $"{nameof(CommonContextForTests)}.{nameof(DefaultDhUser)} and {nameof(CommonContextForTests)}{DefaultDhPassword}");
    }

    var creds = Credentials.OfUsernamePassword(user!, password!, user!);
    var sm = SessionManager.FromUri("C++ Client Test", creds, jsonUrl!, false);
    return sm;
  }

  private static string? TryGetEnv(string envName, string? defaultValue, List<string> failures) {
    var enVal = Environment.GetEnvironmentVariable(envName);
    if (enVal != null) {
      return enVal;
    }
    if (defaultValue != null) {
      return defaultValue;
    }

    failures.Add(envName);
    return null;
  }
}
