//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//
using Io.Deephaven.Proto.Controller;

namespace Deephaven.Dhe_NetClient;

public class Subscription : IDisposable {
  private readonly SubscriptionContext _context;

  internal Subscription(SubscriptionContext context) {
    _context = context;
  }

  public void Dispose() {
    // In the current implementation, all users share the same subscription,
    // so Dispose is a no-op.
  }

  /// <summary>
  /// Gets a snapshot of the current persistent query state.
  /// This method stores two values in its out parameters:
  /// the current version number, which can be used in a subsequent call to `Next`,
  /// and a map of PQ serial to persistent query infos.
  /// Note version number here has nothing to do with a particular
  /// Persistent Query (PQ) version; the version here is a concept about
  /// the subscription information: if version X and version Y are such that
  /// Y > X, that means version Y is newer than X, Y reflects a more recent
  /// snapshot of the state of all PQs in the controller server, as known by the
  /// client at this time.
  ///
  /// Note that the stored map behaves as an immutable map. Multiple versions
  /// of this map share common subtrees. The client can keep a reference to this
  /// map as long as it would like.
  /// </summary>
  /// <param name="version">an out parameter where the current version number will be stored</param>
  /// <param name="map">an output parameter where the current map of PQ state will be stored</param>
  /// <returns>false if this Subscription is closed and shut down already,
  /// in which case the output parameter pointer values are set to default values;
  /// true otherwise. See the documentation for `IsClosed` for
  /// an explanation of how the subscription can become closed</returns>
  public bool Current(out Int64 version,
    out IReadOnlyDictionary<Int64, PersistentQueryInfoMessage> map) =>
      _context.Current(out version, out map);

  /// <summary>
  /// Blocks until deadline, or a new version is available, or the subscription
  /// is closed.
  /// See the note on Current about the meaning of version in the context
  /// of a subscription.
  /// </summary>
  /// <param name="hasNewerVersion">an out parameter whose pointer value will be set to
  /// true if there is a version available more recent than the `version` argument supplied</param>
  /// <param name="version">the version reference used for setting 'hasNewerVersion</param>
  /// <param name="deadline">The deadline</param>
  /// <returns>false if this Subscription is closed and shut down already.
  /// Otherwise true, meaning the deadline was reached, there is a new
  /// version available, or both. Consult hasNewerVersion to
  /// distinguish between these cases</returns>
  public bool Next(out bool hasNewerVersion, Int64 version, DateTimeOffset deadline) =>
    _context.Next(out hasNewerVersion, version, deadline);

  /// <summary>
  /// Blocks until a new version is available, or the subscription is closed.
  /// </summary>
  /// <param name="version">a version reference; next will return true only if a
  /// new version more recent than this argument is available</param>
  /// <returns>false if this Subscription is closed and shut down already,
  /// in which case the output parameter pointer values are set to default values;
  /// true otherwise. See the documentation for `IsClosed` for
  /// an explanation of how the subscription can become closed</returns>
  public bool Next(Int64 version) => _context.Next(version);
}
