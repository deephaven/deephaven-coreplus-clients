//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//

using System.Diagnostics;
using Deephaven.Dh_NetClient;
using Google.Protobuf;
using Grpc.Net.Client;
using Io.Deephaven.Proto.Auth;
using Io.Deephaven.Proto.Controller;
using Io.Deephaven.Proto.Controller.Grpc;

namespace Deephaven.Dhe_NetClient;

public class ControllerClient : IDisposable {
  private static readonly TimeSpan DeadlineSpan = TimeSpan.FromMinutes(2);

  private static readonly string[] DefaultTempScheduling = [
    "SchedulerType=com.illumon.iris.controller.IrisQuerySchedulerTemporary",
    "TemporaryQueueName=InteractiveConsoleTemporaryQueue",
    "TemporaryExpirationTimeMillis=172800000",
    "StartTime=00:00:00",
    "StopTime=23:59:59",
    "TimeZone=America/New_York",
    "SchedulingDisabled=false",
    "Overnight=false",
    "RepeatEnabled=false",
    "SkipIfUnsuccessful=true",
    "StopTimeDisabled=true",
    "RestartErrorCount=0",
    "RestartErrorDelay=0",
    "RestartWhenRunning=false"
  ];

  private const string ControllerServiceName = "PersistentQueryController";

  private static readonly TimeSpan HeartbeatPeriod = TimeSpan.FromSeconds(10);

  public static ControllerClient Connect(string descriptiveName, string target,
    ClientOptions options, AuthClient authClient) {

    // Get an auth token for me from the AuthClient
    var authToken = authClient.CreateToken(ControllerServiceName);

    var channel = GrpcUtil.CreateChannel(target, options);
    // Create the stub
    var controllerApi = new ControllerApi.ControllerApiClient(channel);

    // Authenticate to the controller
    var clientId = ClientUtil.MakeClientId(descriptiveName, Guid.NewGuid().ToByteArray());

    var authReq = new AuthenticationRequest {
      ClientId = clientId,
      Token = AuthUtil.ProtoFromAuthToken(authToken),
      GetConfiguration = true
    };
    var authResp = controllerApi.authenticate(authReq);
    if (!authResp.Authenticated) {
      throw new Exception("Failed to authenticate to the Controller");
    }

    var authCookie = authResp.Cookie.ToByteArray();

    var configReq = new GetConfigurationRequest {
      Cookie = ByteString.CopyFrom(authCookie)
    };
    var configResp = controllerApi.getConfiguration(configReq, null, MakeDeadline());

    var subscriptionContext = SubscriptionContext.Create(controllerApi, authCookie);

    var result = new ControllerClient(clientId, channel, controllerApi,
      subscriptionContext, authCookie, configResp.Config, authToken.UserContext);
    return result;
  }

  private readonly ClientId _clientId;
  private readonly GrpcChannel _channel;
  private readonly ControllerApi.ControllerApiClient _controllerApi;
  private readonly SubscriptionContext _subscriptionContext;
  private readonly Subscription _sharedSubscription;

  /// <summary>
  /// These fields are all protected by a synchronization object
  /// </summary>
  private struct SyncedFields {
    public readonly object SyncRoot = new();
    public readonly byte[] AuthCookie;
    public readonly ControllerConfigurationMessage Config;
    public readonly UserContext UserContext;
    public readonly Timer Keepalive;
    public bool Cancelled = false;

    public SyncedFields(byte[] authCookie, ControllerConfigurationMessage config,
      UserContext userContext, Timer keepalive) {
      AuthCookie = authCookie;
      Config = config;
      UserContext = userContext;
      Keepalive = keepalive;
    }
  }

  private SyncedFields _synced;

  private ControllerClient(ClientId clientId, GrpcChannel channel,
    ControllerApi.ControllerApiClient controllerApi,
    SubscriptionContext subscriptionContext,
    byte[] authCookie, ControllerConfigurationMessage config,
    UserContext userContext) {
    _clientId = clientId;
    _channel = channel;
    _controllerApi = controllerApi;
    _subscriptionContext = subscriptionContext;
    _sharedSubscription = new(_subscriptionContext);
    var keepalive = new Timer(Heartbeat);
    _synced = new SyncedFields(authCookie, config, userContext, keepalive);
    keepalive.Change(HeartbeatPeriod, HeartbeatPeriod);
  }

  public void Dispose() {
    lock (_synced.SyncRoot) {
      if (_synced.Cancelled) {
        return;
      }
      _synced.Cancelled = true;
      _synced.Keepalive.Dispose();
    }
    _subscriptionContext.Dispose();
    _channel.Dispose();
  }

  public Subscription Subscribe() => _sharedSubscription;

  public Int64 AddQuery(PersistentQueryConfigMessage pqConfig) {
    var req = new AddQueryRequest {
      Cookie = GetAuthCookie(),
      Config = pqConfig,
    };
    var resp = _controllerApi.addQuery(req, null, MakeDeadline());
    return resp.QuerySerial;
  }

  public void RestartQuery(Int64 serial) {
    RestartQueries([serial]);
  }

  public void RestartQueries(IEnumerable<Int64> serials) {
    var req = new RestartQueryRequest {
      Cookie = GetAuthCookie()
    };
    req.Serials.Add(serials);
    _ = _controllerApi.restartQuery(req, null, MakeDeadline());
  }

  public void RemoveQuery(Int64 pqSerial) {
    var req = new RemoveQueryRequest {
      Cookie = GetAuthCookie(),
      Serial = pqSerial
    };
    _ = _controllerApi.removeQuery(req, null, MakeDeadline());
  }

  public PersistentQueryConfigMessage MakeTempPqConfig(string pqName) {
    // CheckNotClosedOrThrow();
    ControllerConfigurationMessage controllerConfig;
    string effectiveUser;
    lock (_synced.SyncRoot) {
      controllerConfig = _synced.Config;
      effectiveUser = _synced.UserContext.EffectiveUser;
    }

    var config = new PersistentQueryConfigMessage {
      Name = pqName,
      Version = 1,
      Owner = effectiveUser,
      Serial = Int64.MinValue,
      RestartUsers = RestartUsersEnum.RuAdmin,
      JvmProfile = "Default",
      TimeoutNanos = (Int64)60 * 1_000_000_000,
      WorkerKind = "DeephavenCommunity",
      ScriptLanguage = "Python",
      ConfigurationType = "InteractiveConsole",
      Enabled = true,
      BufferPoolToHeapRatio = 0.25,
      DetailedGCLoggingEnabled = true,
      TypeSpecificFieldsJson = """{ "TerminationDelay" : { "type" : "long", "value" : 600 } }"""
    };

    if (controllerConfig.DbServers.Count > 0) {
      var server = controllerConfig.DbServers[0].Name;
      config.ServerName = server;
    }

    config.Scheduling.AddRange(DefaultTempScheduling);
    config.Scheduling.Add("TemporaryAutoDelete=true");

    return config;
  }

  private ByteString GetAuthCookie() {
    lock (_synced.SyncRoot) {
      return ByteString.CopyFrom(_synced.AuthCookie);
    }
  }

  private static DateTime MakeDeadline() {
    return DateTime.UtcNow + DeadlineSpan;
  }

  /// <summary>
  /// Test if a given status implies a running query.
  /// If not running and not terminal, then the query is in the initialization process.
  /// </summary>
  /// <param name="status">The status</param>
  /// <returns>true if the status represents a running query</returns>
  public static bool IsRunning(PersistentQueryStatusEnum status) {
    return status == PersistentQueryStatusEnum.PqsRunning;
  }

  /// <summary>
  /// Test if a given status implies a terminal (not running) query.
  /// If not running and not terminal, then the query is in the initialization process.
  /// </summary>
  /// <param name="status">The status</param>
  /// <returns>true if the status represents a terminal query</returns>
  public static bool IsTerminal(PersistentQueryStatusEnum status) {
    return status == PersistentQueryStatusEnum.PqsError ||
      status == PersistentQueryStatusEnum.PqsDisconnected ||
      status == PersistentQueryStatusEnum.PqsStopped ||
      status == PersistentQueryStatusEnum.PqsFailed ||
      status == PersistentQueryStatusEnum.PqsCompleted;
  }

  private void Heartbeat(object? unused) {
    PingRequest req;
    lock (_synced.SyncRoot) {
      if (_synced.Cancelled) {
        return;
      }
      req = new PingRequest {
        Cookie = ByteString.CopyFrom(_synced.AuthCookie)
      };
    }

    try {
      _ = _controllerApi.ping(req);
    } catch (Exception e) {
      Debug.WriteLine($"{_clientId}: Controller heartbeat ignoring exception: {e}");

      lock (_synced.SyncRoot) {
        _synced.Keepalive.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
      }
    }
  }
}
