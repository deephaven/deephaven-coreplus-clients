//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//

using System.Diagnostics;
using Google.Protobuf;
using Io.Deephaven.Proto.Auth;
using Io.Deephaven.Proto.Auth.Grpc;
using Grpc.Net.Client;
using Deephaven.Dh_NetClient;

namespace Deephaven.Dhe_NetClient;

public class AuthClient : IDisposable {
  public static AuthClient Connect(string descriptiveName, Credentials credentials,
    string target, ClientOptions options) {
    var channel = GrpcUtil.CreateChannel(target, options);
    var authApi = new AuthApi.AuthApiClient(channel);
    var uuid = System.Guid.NewGuid().ToByteArray();
    var clientId = ClientUtil.MakeClientId(descriptiveName, uuid);
    var (authCookie, deadline) = Authenticate(clientId, authApi, credentials);
    var result = new AuthClient(clientId, channel, authApi, authCookie, deadline);
    return result;
  }

  private static (byte[], long) Authenticate(ClientId clientId,
    AuthApi.AuthApiClient authApi, Credentials credentials) {
    var authResult = credentials switch {
      Credentials.PasswordCredentials pwc => AuthenticateByPassword(clientId, authApi, pwc),
      Credentials.SamlCredentials samlc => AuthenticateBySaml(clientId, authApi, samlc),
      _ => throw new Exception($"Unexpected credentials type {credentials.GetType().Name}")
    };

    if (!authResult.Authenticated) {
      throw new Exception("Authentication failed");
    }

    var cookie = authResult.Cookie.ToByteArray();
    return (cookie, authResult.CookieDeadlineTimeMillis);
  }

  private static AuthenticationResult AuthenticateByPassword(ClientId clientId,
    AuthApi.AuthApiClient authApi, Credentials.PasswordCredentials pwc) {
    var req = new AuthenticateByPasswordRequest {
      ClientId = clientId,
      Password = pwc.Password,
      UserContext = new Io.Deephaven.Proto.Auth.UserContext {
        AuthenticatedUser = pwc.User,
        EffectiveUser = pwc.OperateAs
      }
    };

    return authApi.authenticateByPassword(req).Result;
  }

  private static AuthenticationResult AuthenticateBySaml(ClientId clientId,
    AuthApi.AuthApiClient authApi, Credentials.SamlCredentials samlc) {
    var req = new AuthenticateByExternalRequest {
      ClientId = clientId,
      Key = samlc.Nonce
    };
    return authApi.authenticateByExternal(req).Result;
  }

  private readonly ClientId _clientId;
  private readonly GrpcChannel _channel;
  private readonly AuthApi.AuthApiClient _authApi;
  private readonly CancellationTokenSource _tokenSource;

  /// <summary>
  /// These fields are all protected by a synchronization object
  /// </summary>
  private struct SyncedFields {
    public readonly object SyncRoot = new();
    public byte[] Cookie;

    public SyncedFields(byte[] cookie) {
      Cookie = cookie;
    }
  }

  private SyncedFields _synced;

  private AuthClient(ClientId clientId, GrpcChannel channel, AuthApi.AuthApiClient authApi,
    byte[] cookie, long cookieDeadlineTimeMillis) {
    _clientId = clientId;
    _channel = channel;
    _authApi = authApi;
    _tokenSource = new();
    _synced = new SyncedFields(cookie);
    var delayTime = CalcDelayTime(cookieDeadlineTimeMillis);
    Task.Run(async () => await RefreshCookie(_tokenSource.Token, delayTime));
  }

  public void Dispose() {
    _tokenSource.Cancel();
    _channel.Dispose();
  }

  internal AuthToken CreateToken(string forService) {
    GetTokenRequest request;
    lock (_synced.SyncRoot) {
      request = new GetTokenRequest {
        Service = forService,
        Cookie = ByteString.CopyFrom(_synced.Cookie)
      };
    }
    var response = _authApi.getToken(request);
    return AuthUtil.AuthTokenFromProto(response.Token);
  }

  private async Task RefreshCookie(CancellationToken token, TimeSpan delayTime) {
    delayTime = TimeSpan.FromSeconds(30);
    while (true) {
      try {
        await Task.Delay(delayTime, token);

        RefreshCookieRequest req;
        lock (_synced.SyncRoot) {
          req = new RefreshCookieRequest {
            Cookie = ByteString.CopyFrom(_synced.Cookie)
          };
        }

        var resp = _authApi.refreshCookie(req);
        delayTime = CalcDelayTime(resp.CookieDeadlineTimeMillis);

        // Empty Cookie means reuse same cookie with new deadline.
        if (resp.Cookie.Length != 0) {
          lock (_synced.SyncRoot) {
            _synced.Cookie = resp.Cookie.ToByteArray();
          }
        }
      } catch (Exception ex) {
        // Whether delay cancelled, Ping exception, or other exception, exit heartbeat loop.
        Debug.WriteLine($"AuthClient heartbeat ending: {ex}");
        return;
      }
    }
  }

  private static TimeSpan CalcDelayTime(long cookieDeadlineTimeMillis) {
    var deadline = DateTimeOffset.FromUnixTimeMilliseconds(cookieDeadlineTimeMillis);
    var delayMillis = (int)(Math.Max(0,
      (deadline - DateTimeOffset.Now).TotalMilliseconds) / 2);
    return TimeSpan.FromMilliseconds(delayMillis);
  }
}
