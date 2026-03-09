package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// newTestLogger returns a discard logger suitable for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// rpcHandler is a configurable httptest handler that serves JSON-RPC responses.
type rpcHandler struct {
	// responses maps method+blockRef → raw result value to return.
	// For methods that don't depend on params, key is just the method name.
	responses map[string]any
	// errors maps method name → rpcError to return for every call to that method.
	errors map[string]*rpcError
	// calls records every method name that was called, in order.
	calls []string
}

func newRPCHandler() *rpcHandler {
	return &rpcHandler{
		responses: make(map[string]any),
		errors:    make(map[string]*rpcError),
	}
}

func (h *rpcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	h.calls = append(h.calls, req.Method)

	w.Header().Set("Content-Type", "application/json")

	if rpcErr, ok := h.errors[req.Method]; ok {
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   rpcErr,
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	result, ok := h.responses[req.Method]
	if !ok {
		http.Error(w, "method not found", http.StatusNotFound)
		return
	}

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      req.ID,
		"result":  result,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// blockResponse builds a fake eth_getBlockByNumber result with the given block
// number and UNIX timestamp.
func blockResponse(number uint64, ts uint64) map[string]string {
	return map[string]string{
		"number":    "0x" + strconv.FormatUint(number, 16),
		"timestamp": "0x" + strconv.FormatUint(ts, 16),
	}
}

// newCheckerWithHandler creates an ActivityChecker backed by a test HTTP server.
func newCheckerWithHandler(h http.Handler) (*ActivityChecker, *httptest.Server) {
	srv := httptest.NewServer(h)
	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())
	return checker, srv
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

const (
	testAddress  = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	testBlockNum = uint64(20_000_000)
)

func testBlockTS() uint64 {
	return uint64(time.Now().UTC().Unix())
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestIsActive_RecentVerification checks that a contract verified less than
// minDays ago is immediately marked active without any RPC calls.
func TestIsActive_RecentVerification(t *testing.T) {
	h := newRPCHandler()
	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	// Verified 1 day ago — well within the 30-day window.
	verifiedAt := time.Now().UTC().Add(-24 * time.Hour)

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true for recently verified contract, got false; reason: %s", result.Reason)
	}
	// No RPC calls should have been made.
	if len(h.calls) != 0 {
		t.Errorf("expected no RPC calls for fast-path, but got: %v", h.calls)
	}
}

// TestIsActive_RecentVerification_ExactCutoff verifies that a contract verified
// exactly at the boundary (minDays ago to the second) is treated as NOT recent —
// the cutoff is exclusive.
func TestIsActive_RecentVerification_ExactCutoff(t *testing.T) {
	// We need a handler that:
	//  - returns a "latest" block whose timestamp is in the future relative to
	//    the cutoff (so the "latestTimestamp <= cutoffUnix" early-return is NOT
	//    taken), AND
	//  - serves bisection calls (any numbered block) with an old timestamp so
	//    bisection converges quickly, AND
	//  - returns no logs so the contract ends up inactive.
	nowTS := uint64(time.Now().UTC().Unix())
	oldTS := uint64(time.Now().UTC().AddDate(-1, 0, 0).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var result any
		switch req.Method {
		case "eth_getBlockByNumber":
			var blockRef string
			if len(req.Params) > 0 {
				_ = json.Unmarshal([]byte(`"`), &blockRef) // reset
				raw, _ := json.Marshal(req.Params[0])
				_ = json.Unmarshal(raw, &blockRef)
			}
			if blockRef == "latest" {
				// Latest block has a current timestamp so we enter the bisect path.
				result = blockResponse(testBlockNum, nowTS)
			} else {
				// Any numbered block during bisection gets an old timestamp.
				result = blockResponse(testBlockNum/2, oldTS)
			}
		case "eth_getLogs":
			result = []any{}
		default:
			http.Error(w, "method not found", http.StatusNotFound)
			return
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	// Exactly 30 days ago — should NOT satisfy the "recent" fast-path.
	verifiedAt := time.Now().UTC().AddDate(0, 0, -30)

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Not recent + no logs → inactive.
	if result.Active {
		t.Errorf("expected Active=false for contract verified exactly at cutoff, got true; reason: %s", result.Reason)
	}
}

// TestIsActive_ActiveLogs checks that a contract with recent logs is marked active.
func TestIsActive_ActiveLogs(t *testing.T) {
	h := newRPCHandler()
	h.responses["eth_getBlockByNumber"] = blockResponse(testBlockNum, testBlockTS())
	// Return 3 fake log entries.
	h.responses["eth_getLogs"] = []map[string]string{
		{"transactionHash": "0xaaa"},
		{"transactionHash": "0xbbb"},
		{"transactionHash": "0xccc"},
	}

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	// verifiedAt is old — should fall through to the logs check.
	verifiedAt := time.Now().UTC().AddDate(0, -6, 0) // 6 months ago

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true for contract with recent logs, got false; reason: %s", result.Reason)
	}
	if result.LogsFound != 3 {
		t.Errorf("expected LogsFound=3, got %d", result.LogsFound)
	}
	if result.LatestBlock != testBlockNum {
		t.Errorf("expected LatestBlock=%d, got %d", testBlockNum, result.LatestBlock)
	}
}

// TestIsActive_InactiveLogs checks that a contract with no recent logs and an
// old verification is marked inactive.
func TestIsActive_InactiveLogs(t *testing.T) {
	h := newRPCHandler()
	h.responses["eth_getBlockByNumber"] = blockResponse(testBlockNum, testBlockTS())
	h.responses["eth_getLogs"] = []any{} // empty

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	verifiedAt := time.Now().UTC().AddDate(0, -3, 0) // 3 months ago

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Active {
		t.Errorf("expected Active=false for contract with no recent logs, got true; reason: %s", result.Reason)
	}
	if result.LogsFound != 0 {
		t.Errorf("expected LogsFound=0, got %d", result.LogsFound)
	}
}

// TestIsActive_NoVerificationDate checks the path where verifiedAt is zero —
// only the RPC logs check is performed.
func TestIsActive_NoVerificationDate(t *testing.T) {
	h := newRPCHandler()
	h.responses["eth_getBlockByNumber"] = blockResponse(testBlockNum, testBlockTS())
	h.responses["eth_getLogs"] = []map[string]string{
		{"transactionHash": "0x111"},
	}

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	result, err := checker.IsActive(context.Background(), testAddress, time.Time{}, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true when logs found and no verifiedAt, got false; reason: %s", result.Reason)
	}
}

// TestIsActive_NoVerificationDate_NoLogs checks that a contract with no
// verification date and no logs is inactive.
func TestIsActive_NoVerificationDate_NoLogs(t *testing.T) {
	h := newRPCHandler()
	h.responses["eth_getBlockByNumber"] = blockResponse(testBlockNum, testBlockTS())
	h.responses["eth_getLogs"] = []any{}

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	result, err := checker.IsActive(context.Background(), testAddress, time.Time{}, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Active {
		t.Errorf("expected Active=false with no verifiedAt and no logs, got true; reason: %s", result.Reason)
	}
}

// TestIsActive_GetBlockError checks that an error from eth_getBlockByNumber is
// propagated as a non-nil error return.
func TestIsActive_GetBlockError(t *testing.T) {
	h := newRPCHandler()
	h.errors["eth_getBlockByNumber"] = &rpcError{Code: -32603, Message: "internal error"}

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	// 1 year ago — unambiguously outside the 30-day window, so the fast path
	// is not taken and we reach the RPC call.
	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0)

	_, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err == nil {
		t.Fatal("expected error from getLatestBlock, got nil")
	}
}

// TestIsActive_GetLogsError checks that a failing eth_getLogs call results in
// Active=false (conservative non-fatal path) rather than a returned error.
func TestIsActive_GetLogsError(t *testing.T) {
	h := newRPCHandler()
	h.responses["eth_getBlockByNumber"] = blockResponse(testBlockNum, testBlockTS())
	h.errors["eth_getLogs"] = &rpcError{Code: -32005, Message: "query returned more than 10000 results"}

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0) // 1 year ago

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("expected no error for non-fatal getLogs failure, got: %v", err)
	}
	if result.Active {
		t.Errorf("expected Active=false when getLogs errors (conservative), got true; reason: %s", result.Reason)
	}
}

// TestIsActive_DefaultMinDays verifies that passing minDays=0 uses the
// defaultMinAgeDays constant (30) and does not panic.
func TestIsActive_DefaultMinDays(t *testing.T) {
	h := newRPCHandler()
	h.responses["eth_getBlockByNumber"] = blockResponse(testBlockNum, testBlockTS())
	h.responses["eth_getLogs"] = []any{}

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0) // 1 year ago

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Old contract + no logs → inactive.
	if result.Active {
		t.Errorf("expected Active=false with default window, got true; reason: %s", result.Reason)
	}
}

// TestIsActive_BisectFromBlock verifies that the binary search converges on the
// correct fromBlock. We use a synthetic chain with a known genesis time and a
// fixed block time so the expected fromBlock is trivially computable:
//
//	timestamp(block N) = genesisTS + N * blockSecs
//	fromBlock          = ceil((cutoffUnix - genesisTS) / blockSecs)
func TestIsActive_BisectFromBlock(t *testing.T) {
	const (
		minDays     = 7
		blockSecs   = uint64(12)         // Ethereum-like
		latestBlock = uint64(10_000_000) // number of blocks
	)

	// Anchor latestTS at now so the chain definitely extends past any cutoff.
	latestTS := uint64(time.Now().UTC().Unix())
	genesisTS := latestTS - latestBlock*blockSecs

	cutoffUnix := uint64(time.Now().UTC().AddDate(0, 0, -minDays).Unix())
	// Expected fromBlock: first block whose ts >= cutoffUnix.
	// ts(N) = genesisTS + N*blockSecs  =>  N = ceil((cutoffUnix - genesisTS) / blockSecs)
	expectedFromBlock := (cutoffUnix - genesisTS + blockSecs - 1) / blockSecs

	var capturedFromBlock uint64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var result any
		switch req.Method {
		case "eth_getBlockByNumber":
			// After JSON decode, Params[0] is a plain Go string.
			blockRef, _ := req.Params[0].(string)
			var blockNum uint64
			if blockRef == "latest" {
				blockNum = latestBlock
			} else {
				blockNum, _ = hexToUint64(blockRef)
			}
			ts := genesisTS + blockNum*blockSecs
			result = blockResponse(blockNum, ts)

		case "eth_getLogs":
			// Capture fromBlock for assertion.
			if len(req.Params) > 0 {
				raw, _ := json.Marshal(req.Params[0])
				var filter map[string]string
				if err := json.Unmarshal(raw, &filter); err == nil {
					capturedFromBlock, _ = hexToUint64(filter["fromBlock"])
				}
			}
			result = []any{}

		default:
			http.Error(w, "method not found", http.StatusNotFound)
			return
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0) // 1 year ago — no fast path

	// Sanity: latest block must be newer than the cutoff so we don't hit the
	// "entire chain within window" early return.
	if latestTS <= cutoffUnix {
		t.Fatalf("test setup broken: latestTS %d <= cutoffUnix %d", latestTS, cutoffUnix)
	}

	_, err := checker.IsActive(context.Background(), testAddress, verifiedAt, minDays)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allow ±1 block tolerance for bisection rounding.
	diff := int64(capturedFromBlock) - int64(expectedFromBlock)
	if diff < -1 || diff > 1 {
		t.Errorf("fromBlock bisection: got %d, expected ~%d (diff=%d, blockSecs=%d)",
			capturedFromBlock, expectedFromBlock, diff, blockSecs)
	}
}

// TestIsActive_LowBlockNumber verifies behaviour when the entire chain history
// fits within the look-back window (e.g. a very new chain or test environment).
// bisectFromBlock must not underflow and the fromBlock passed to eth_getLogs
// must be <= the chain height (100 in this test).
func TestIsActive_LowBlockNumber(t *testing.T) {
	const chainHeight = uint64(100)
	var capturedFromBlock uint64
	captured := false

	// All blocks (including "latest" and any numbered block) have a timestamp
	// that is 2 years in the past — well outside any 30-day window — so the
	// "latestTimestamp <= cutoffUnix" fast-return is NOT triggered (that branch
	// fires when latestTS <= cutoff, meaning the latest block is *older* than
	// the window which is the opposite of what a live chain would look like).
	//
	// Wait — we actually DO want to test bisection here. To avoid the early
	// return we need latestTimestamp > cutoffUnix. Use a timestamp of "now"
	// for "latest" but an old timestamp for numbered blocks during bisection
	// so bisection converges to a small fromBlock.
	nowTS := uint64(time.Now().UTC().Unix())
	oldTS := uint64(time.Now().UTC().AddDate(-2, 0, 0).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var result any
		switch req.Method {
		case "eth_getBlockByNumber":
			blockRef, _ := req.Params[0].(string)
			if blockRef == "latest" {
				result = blockResponse(chainHeight, nowTS)
			} else {
				// Numbered block during bisection: return an old timestamp so
				// bisection pushes fromBlock toward 0.
				n, _ := hexToUint64(blockRef)
				result = blockResponse(n, oldTS)
			}
		case "eth_getLogs":
			if len(req.Params) > 0 {
				raw, _ := json.Marshal(req.Params[0])
				var filter map[string]string
				if err := json.Unmarshal(raw, &filter); err == nil {
					capturedFromBlock, _ = hexToUint64(filter["fromBlock"])
					captured = true
				}
			}
			result = []any{}
		default:
			http.Error(w, "method not found", http.StatusNotFound)
			return
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0)

	_, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !captured {
		t.Fatal("eth_getLogs was never called; fromBlock was not captured")
	}
	if capturedFromBlock > chainHeight {
		t.Errorf("expected fromBlock <= %d for a chain of height %d, got %d",
			chainHeight, chainHeight, capturedFromBlock)
	}
}

// TestIsActive_LatestWithinWindow verifies that when the latest block's
// timestamp is at or before the cutoff (i.e. the entire chain is "older" than
// the window, as can happen in test environments or brand-new chains) the
// function returns Active=true immediately without calling eth_getLogs.
func TestIsActive_LatestWithinWindow(t *testing.T) {
	h := newRPCHandler()
	// The latest block has a timestamp that is 2 years in the past — so
	// latestTimestamp <= cutoffUnix, which triggers the early-return branch.
	oldBlockTS := uint64(time.Now().UTC().AddDate(-2, 0, 0).Unix())
	h.responses["eth_getBlockByNumber"] = blockResponse(10, oldBlockTS)
	// eth_getLogs must NOT be called (we never set a response for it).

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	// Old verifiedAt so we skip the Sourcify fast-path.
	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0)

	result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true when latest block timestamp is within the window, got false; reason: %s", result.Reason)
	}
	// Confirm eth_getLogs was never called.
	for _, call := range h.calls {
		if call == "eth_getLogs" {
			t.Error("eth_getLogs should not have been called in the early-return path")
		}
	}
}

// TestIsActive_HTTPError checks that a non-200 HTTP response is returned as an
// error from IsActive.
func TestIsActive_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	// 1 year ago — unambiguously outside the 30-day window.
	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0)

	_, err := checker.IsActive(context.Background(), testAddress, verifiedAt, 30)
	if err == nil {
		t.Fatal("expected error from HTTP 503 response, got nil")
	}
}

// TestIsActive_CancelledContext ensures that a cancelled context propagates as
// an error.
func TestIsActive_CancelledContext(t *testing.T) {
	h := newRPCHandler()
	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// 1 year ago — unambiguously outside the 30-day window.
	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0)

	_, err := checker.IsActive(ctx, testAddress, verifiedAt, 30)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// TestHexToUint64 exercises the internal hex conversion helper.
func TestHexToUint64(t *testing.T) {
	tests := []struct {
		input   string
		want    uint64
		wantErr bool
	}{
		{"0x0", 0, false},
		{"0x1", 1, false},
		{"0xff", 255, false},
		{"0xFF", 255, false},
		{"0x131AEF", 1252079, false},
		{"0X10", 16, false},
		{"", 0, false},
		{"0xzz", 0, true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("input=%q", tc.input), func(t *testing.T) {
			got, err := hexToUint64(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (result=%d)", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("hexToUint64(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestNewActivityChecker_Defaults verifies that a nil HTTP client is handled
// gracefully and a default client is created.
func TestNewActivityChecker_Defaults(t *testing.T) {
	checker := NewActivityChecker("http://localhost:8545", nil, newTestLogger())
	if checker.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
}

// TestIsActive_BisectionCachedAcrossCalls verifies that the bisection RPC calls
// (eth_getBlockByNumber for numbered blocks) are only made once regardless of
// how many times IsActive is called on the same checker within the same day.
// Subsequent calls must reuse the cached fromBlock and only issue eth_getLogs.
func TestIsActive_BisectionCachedAcrossCalls(t *testing.T) {
	const (
		minDays     = 7
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
	)

	latestTS := uint64(time.Now().UTC().Unix())
	genesisTS := latestTS - latestBlock*blockSecs

	// Count how many times eth_getBlockByNumber is called with a numbered
	// block ref (i.e. bisection calls, not the "latest" anchor call).
	var bisectCalls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var result any
		switch req.Method {
		case "eth_getBlockByNumber":
			blockRef, _ := req.Params[0].(string)
			var blockNum uint64
			if blockRef == "latest" {
				blockNum = latestBlock
			} else {
				bisectCalls++
				blockNum, _ = hexToUint64(blockRef)
			}
			ts := genesisTS + blockNum*blockSecs
			result = blockResponse(blockNum, ts)

		case "eth_getLogs":
			result = []any{} // no logs — contract inactive

		default:
			http.Error(w, "method not found", http.StatusNotFound)
			return
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())
	verifiedAt := time.Now().UTC().AddDate(-1, 0, 0) // old — no fast path

	const numCalls = 5
	for i := range numCalls {
		result, err := checker.IsActive(context.Background(), testAddress, verifiedAt, minDays)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		// All calls should return the same Active=false result (no logs).
		if result.Active {
			t.Errorf("call %d: expected Active=false, got true; reason: %s", i, result.Reason)
		}
	}

	// Bisection should have run exactly once; all subsequent calls must use the
	// cache and skip the numbered eth_getBlockByNumber calls entirely.
	if bisectCalls == 0 {
		t.Error("expected at least one bisection call on the first IsActive invocation")
	}
	bisectCallsAfterFirst := bisectCalls
	// Run one more batch to confirm the count doesn't grow.
	for i := range numCalls {
		_, err := checker.IsActive(context.Background(), testAddress, verifiedAt, minDays)
		if err != nil {
			t.Fatalf("second batch call %d: unexpected error: %v", i, err)
		}
	}
	if bisectCalls != bisectCallsAfterFirst {
		t.Errorf("bisection ran again on subsequent calls: before=%d after=%d; cache is not working",
			bisectCallsAfterFirst, bisectCalls)
	}
}
