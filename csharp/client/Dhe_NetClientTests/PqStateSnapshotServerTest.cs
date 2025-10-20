//
// Copyright (c) 2016-2025 Deephaven Data Labs and Patent Pending
//
using Deephaven.Dhe_NetClient;
using Xunit.Abstractions;

namespace Deephaven.Dhe_NetClientTests;

public class PqStateSnapshotServerTest(ITestOutputHelper output) {
  [Fact]
  public void PqFoundInSubscription() {
    using var ctx = CommonContextForTests.Create();
    var sm = ctx.SessionManager;

    output.WriteLine("Creating PQ 1...");
    var client1 = MakePq(sm, "cpp_test_pq_1");
    output.WriteLine("Creating PQ 2...");
    var client2 = MakePq(sm, "cpp_test_pq_2");
    var serial1 = client1.PqSerial;
    var serial2 = client2.PqSerial;

    using var sub = sm.Subscribe();
    output.WriteLine("Waiting for both PQs to come up...");
    if (!WaitForState(sub, serial1, true, serial2, true, out var errorMessage)) {
      throw new Exception($"While waiting for both PQs: {errorMessage}");
    }
    output.WriteLine("Waiting for second to be removed...");
    sm.RemoveQuery(serial2);
    if (!WaitForState(sub, serial1, true, serial2, false, out errorMessage)) {
      throw new Exception($"While waiting for second PQ to be removed: {errorMessage}");
    }
    output.WriteLine("Waiting for first to be removed");
    sm.RemoveQuery(serial1);
    if (!WaitForState(sub, serial1, false, serial2, false, out errorMessage)) {
      throw new Exception($"While waiting for first PQ to be removed: {errorMessage}");
    }
  }

  private static DndClient MakePq(SessionManager sm, string pqName) {
    var pq = sm.MakeTempPqConfig(pqName);
    pq.ScriptLanguage = "python"; 
    pq.HeapSizeGb = 4;
    var client = sm.AddQueryAndConnect(pq);
    return client;
  }

  private static bool WaitForState(Subscription sub, Int64 serial1, bool expectS1Present,
    Int64 serial2, bool expectS2Present, out string errorMessage) {

    // We will give the server 15 seconds to settle to the state we expect
    var deadline = DateTimeOffset.Now + TimeSpan.FromSeconds(15);

    while (true) {
      if (!sub.Current(out var version, out var map)) {
        errorMessage = "Subscription closed when calling Current";
        return false;
      }

      var s1Present = map.ContainsKey(serial1);
      var s2Present = map.ContainsKey(serial2);

      if (s1Present == expectS1Present && s2Present == expectS2Present) {
        errorMessage = "";
        return true;
      }

      if (!sub.Next(out var hasNewer, version, deadline)) {
        errorMessage = "Subscription closed when calling Next";
        return false;
      }

      if (!hasNewer) {
        errorMessage = "Timeout";
        return false;
      }
    }
  }
}

