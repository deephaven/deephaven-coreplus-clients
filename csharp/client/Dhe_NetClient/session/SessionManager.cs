//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//
using Deephaven.Dh_NetClient;
using Io.Deephaven.Proto.Controller;

namespace Deephaven.Dhe_NetClient;

public class SessionManager : IDisposable {
  /// <summary>
  /// A synchronization object for ActiveNonces
  /// </summary>
  private static readonly object Sync = new();
  /// <summary>
  /// The set of nonces that have been used for SAML authentication. This allows the caller
  /// to connect to another session with the same nonce without another browser interaction.
  /// In a future PR we will time out these entries.
  /// </summary>
  private static readonly HashSet<string> ActiveNonces = new();

  private const string DefaultOverrideAuthority = "authserver";
  private const string DispatcherServiceName = "RemoteQueryProcessor";

  /// <summary>
  /// Creates a SessionManager from a URI (specified as a string)
  /// </summary>
  /// <param name="descriptiveName">A descriptive name of this SessionManager (for debugging/logging)</param>
  /// <param name="credentials">The credentials to authenticate to the server</param>
  /// <param name="url">The URL of the server (e.g. https://myserver.mycorp:8123/iris/connection.json)</param>
  /// <param name="validateCertificate">Whether you want to validate the servers SSL certificate</param>
  /// <param name="invokeBrowser">If the credentials type is SAML, a callback we will invoke containing a URI
  /// which needs to be passed to a browser for the user to authenticate. This callback must invoke the
  /// browser in the background and not block.</param>
  /// <returns>The new SessionManager</returns>
  public static SessionManager FromUri(string descriptiveName, Credentials credentials,
    string url, bool validateCertificate = true, Action<Uri>? invokeBrowser = null) {
    var uri = new Uri(url);
    return FromUri(descriptiveName, credentials, uri, validateCertificate, invokeBrowser);
  }

  /// <summary>
  /// Creates a SessionManager from a uri.
  /// </summary>
  /// <param name="descriptiveName">A descriptive name of this SessionManager (for debugging/logging)</param>
  /// <param name="credentials">The credentials to authenticate to the server</param>
  /// <param name="uri">The URI of the server (e.g. https://myserver.mycorp:8123/iris/connection.json)</param>
  /// <param name="validateCertificate">Whether you want to validate the servers SSL certificate</param>
  /// <param name="invokeBrowser">If the credentials type is SAML, a callback we will invoke containing a URI
  /// which needs to be passed to a browser for the user to authenticate. This callback must invoke the
  /// browser in the background and not block.</param>
  /// <returns>The new SessionManager</returns>
  public static SessionManager FromUri(string descriptiveName, Credentials credentials,
    Uri uri, bool validateCertificate = true, Action<Uri>? invokeBrowser = null) {
    var info = ConfigurationInfo.OfUri(uri, validateCertificate);
    return FromConfigInfo(descriptiveName, credentials, info, invokeBrowser);
  }

  /// <summary>
  /// Creates a SessionManager from a JSON file.
  /// </summary>
  /// <param name="descriptiveName">A descriptive name of this SessionManager (for debugging/logging)</param>
  /// <param name="credentials">The credentials to authenticate to the server</param>
  /// <param name="json">The JSON file as returned by a Deephaven server when fetching
  /// e.g. https://myserver.mycorp:8123/iris/connection.json</param>
  /// <param name="invokeBrowser">If the credentials type is SAML, a callback we will invoke containing a URI
  /// which needs to be passed to a browser for the user to authenticate. This callback must invoke the
  /// browser in the background and not block.</param>
  /// <returns>The new SessionManager</returns>
  public static SessionManager FromJson(string descriptiveName, Credentials credentials,
    string json, Action<Uri>? invokeBrowser = null) {
    var info = ConfigurationInfo.OfJson(json);
    return FromConfigInfo(descriptiveName, credentials, info, invokeBrowser);
  }

  public static SessionManager FromConfigInfo(string descriptiveName, Credentials credentials,
    ConfigurationInfo info, Action<Uri>? invokeBrowser) {
    string? rootCerts = null;
    if (info.TruststoreUrl != null) {
      // TODO(kosak): true, false, or pass through some parameter?
      rootCerts = GetUrl(info.TruststoreUrl, false);
    }

    string? authAuthority = null;
    string? controllerAuthority = null;
    if (info.OverrideAuthorities) {
      authAuthority = info.AuthAuthority ?? DefaultOverrideAuthority;
      controllerAuthority = info.ControllerAuthority ?? DefaultOverrideAuthority;
    }

    ArgumentNullException.ThrowIfNull(authAuthority, nameof(authAuthority));
    ArgumentNullException.ThrowIfNull(controllerAuthority, nameof(controllerAuthority));
    ArgumentNullException.ThrowIfNull(rootCerts, nameof(rootCerts));

    if (credentials is Credentials.SamlCredentials saml) {
      if (invokeBrowser == null) {
        throw new Exception("Credentials is of type SAML but no browser callback provided");
      }
      bool needToInvokeBrowser;
      lock (Sync) {
        needToInvokeBrowser = ActiveNonces.Add(saml.Nonce);
      }

      if (needToInvokeBrowser) {
        var uri = info.MakeSamlAuthUri(saml.Nonce);
        invokeBrowser(uri);
      }
    }

    return Create(
      descriptiveName,
      credentials,
      info.AuthHost[0], info.AuthPort,
      authAuthority,
      info.ControllerHost, info.ControllerPort,
      controllerAuthority,
      rootCerts);
  }

  private static SessionManager Create(
    string descriptiveName, Credentials credentials,
    string authHost, UInt16 authPort, string authAuthority,
    string controllerHost, UInt16 controllerPort, string controllerAuthority,
    string rootCerts) {
    var (authTarget, authOptions) = SetupClientOptions(authHost, authPort,
      authAuthority, rootCerts);
    var authClient = AuthClient.Connect(descriptiveName, credentials, authTarget, authOptions);
    var (controllerTarget, controllerOptions) = SetupClientOptions(
      controllerHost, controllerPort,
      controllerAuthority, rootCerts);
    var controllerClient = ControllerClient.Connect(descriptiveName,
      controllerTarget, controllerOptions, authClient);
    return new SessionManager(descriptiveName, authClient, controllerClient,
      authAuthority, controllerAuthority, rootCerts);
  }

  private static (string, ClientOptions) SetupClientOptions(string host, UInt16 port,
    string? overrideAuthority, string rootCerts) {
    var target = $"{host}:{port}";
    var clientOptions = new ClientOptions {
      UseTls = true,
      TlsRootCerts = rootCerts,
      OverrideAuthority = overrideAuthority != null
    };

    return (target, clientOptions);
  }

  private readonly string _logId;
  private readonly AuthClient _authClient;
  private readonly ControllerClient _controllerClient;
  private readonly string _authAuthority;
  private readonly string _controllerAuthority;
  private readonly string _rootCerts;

  private SessionManager(string logId, AuthClient authClient, ControllerClient controllerClient,
    string authAuthority, string controllerAuthority, string rootCerts) {
    _logId = logId;
    _authClient = authClient;
    _controllerClient = controllerClient;
    _authAuthority = authAuthority;
    _controllerAuthority = controllerAuthority;
    _rootCerts = rootCerts;
  }

  public void Dispose() {
    _controllerClient.Dispose();
    _authClient.Dispose();
  }

  public DndClient AddQueryAndConnect(PersistentQueryConfigMessage pqConfig) {
    var serial = AddQueryAndStart(pqConfig);
    var client = ConnectToPqById(serial, true);
    return client;
  }

  public Int64 AddQueryAndStart(PersistentQueryConfigMessage pqConfig) {
    var serial = _controllerClient.AddQuery(pqConfig);
    _controllerClient.RestartQuery(serial);
    return serial;
  }

  public PersistentQueryConfigMessage MakeTempPqConfig(string pqName) {
    return _controllerClient.MakeTempPqConfig(pqName);
  }

  public DndClient ConnectToPqByName(string pqName, bool removeOnClose) {
    var (pqSerial, client) = FindPqAndConnect(dict => {
      var result = dict.Values.FirstOrDefault(i => i.Config.Name == pqName);
      if (result == null) {
        throw new Exception($"pq name='{pqName}' not found");
      }
      return result;
    });
    return DndClient.Create(pqSerial, this, client, removeOnClose);
  }

  public DndClient ConnectToPqById(Int64 pqSerial, bool removeOnClose) {
    var (_, client) = FindPqAndConnect(dict => {
      if (!dict.TryGetValue(pqSerial, out var result)) {
        throw new Exception($"pqSerial='{pqSerial}' not found");
      }
      return result;
    });
    return DndClient.Create(pqSerial, this, client, removeOnClose);
  }

  private (Int64, Client) FindPqAndConnect(
    Func<IReadOnlyDictionary<Int64, PersistentQueryInfoMessage>, PersistentQueryInfoMessage> filter) {
    using var subscription = _controllerClient.Subscribe();
    if (!subscription.Current(out var version, out var configMap)) {
      throw new Exception("Controller subscription has closed");
    }

    var info = filter(configMap);
    var pqSerial = info.Config.Serial;
    var pqName = info.Config.Name;

    while (true) {
      // It may make sense to have the ability to provide a timeout
      // in the future; absent a terminal or running state being found or
      // the subscription closing, as is this will happily run forever.
      var status = info.State.Status;
      if (ControllerClient.IsTerminal(status)) {
        throw new Exception($"pqName='{pqName}', pqSerial={pqSerial} " +
          $"is in terminal state={info.State.Status}");
      }

      if (ControllerClient.IsRunning(status)) {
        break;
      }

      if (!subscription.Next(version) ||
          !subscription.Current(out version, out configMap)) {
        throw new Exception("Controller subscription has closed");
      }

      if (!configMap.TryGetValue(pqSerial, out info)) {
        throw new Exception($"pqName='{pqName}', pqSerial={pqSerial} " +
          $"is no longer available");
      }
    }

    return ConnectToPq(info);
  }

  private (Int64, Client) ConnectToPq(PersistentQueryInfoMessage infoMsg) {
    var url = infoMsg.State.ConnectionDetails.GrpcUrl;
    var pqSerial = infoMsg.Config.Serial;

    var pqStrForErr = $"pq_name='{infoMsg.Config.Name}', pq_serial={pqSerial}";

    if (url.IsEmpty()) {
      if (infoMsg.State.EngineVersion.IsEmpty()) {
        throw new Exception($"{pqStrForErr} is not a Community engine");
      }
      throw new Exception($"{pqStrForErr} has no gRPC connectivity available");
    }

    Uri uri;
    try {
      uri = new Uri(url);
    } catch (Exception e) {
      throw new Exception($"{pqStrForErr} has invalid url='{url}'", e);
    }

    var connectionString = $"{uri.Host}:{uri.Port}";
    var envoyPrefix = infoMsg.State.ConnectionDetails.EnvoyPrefix;
    var scriptLanguage = infoMsg.Config.ScriptLanguage;
    var useTls = uri.Scheme == Uri.UriSchemeHttps;
    return ConnectToDndWorker(
      pqSerial,
      connectionString,
      useTls,
      envoyPrefix,
      scriptLanguage);
  }

  private (Int64, Client) ConnectToDndWorker(
    Int64 pqSerial,
    string target,
    bool useTls,
    string envoyPrefix,
    string scriptLanguage) {
    var clientOptions = new ClientOptions();
    if (!envoyPrefix.IsEmpty()) {
      clientOptions.AddExtraHeader("envoy-prefix", envoyPrefix);
    }
    clientOptions.SetSessionType(scriptLanguage);

    if (useTls) {
      clientOptions.SetUseTls(true);
    }
    if (!_rootCerts.IsEmpty()) {
      clientOptions.SetTlsRootCerts(_rootCerts);
    }
    var authToken = _authClient.CreateToken(DispatcherServiceName);
    clientOptions.SetCustomAuthentication(
      "io.deephaven.proto.auth.Token",
      AuthUtil.AsBase64Proto(authToken));

    var client = Client.Connect(target, clientOptions);
    return (pqSerial, client);
  }


  public Subscription Subscribe() => _controllerClient.Subscribe();

  public void RemoveQuery(Int64 pqSerial) {
    _controllerClient.RemoveQuery(pqSerial);
  }

  private static string GetUrl(string url, bool validateCertificate) {
    var handler = new HttpClientHandler();
    if (!validateCertificate) {
      handler.ClientCertificateOptions = ClientCertificateOption.Manual;
      handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
    }
    using var hc = new HttpClient(handler);
    var result = hc.GetStringAsync(url).Result;
    return result;
  }
}
