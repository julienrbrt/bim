package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// newTestLogger returns a discard logger suitable for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// rpcHandler is a configurable httptest handler that serves JSON-RPC responses.
type rpcHandler struct {
	// responses maps method name → raw result value to return.
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

// blockResponse builds a fake eth_getBlockByNumber result.
func blockResponse(number uint64, ts uint64) map[string]string {
	return map[string]string{
		"number":    fmt.Sprintf("0x%x", number),
		"timestamp": fmt.Sprintf("0x%x", ts),
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

func nowTS() uint64 { return uint64(time.Now().UTC().Unix()) }

// syntheticChain returns a handler for a chain where:
//
//	timestamp(block N) = genesisTS + N * blockSecs
//
// The latest block is latestBlock. Callers can override eth_getLogs by setting
// a non-nil logsResult.
func syntheticChain(t *testing.T, genesisTS, latestBlock, blockSecs uint64, logsResult any) (http.Handler, *int) {
	t.Helper()
	bisectCalls := new(int)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			var n uint64
			if blockRef == "latest" {
				n = latestBlock
			} else {
				*bisectCalls++
				n, _ = hexToUint64(blockRef)
			}
			result = blockResponse(n, genesisTS+n*blockSecs)

		case "eth_getLogs":
			if logsResult != nil {
				result = logsResult
			} else {
				result = []any{}
			}

		default:
			http.Error(w, "method not found", http.StatusNotFound)
			return
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
		_ = json.NewEncoder(w).Encode(resp)
	}), bisectCalls
}

// TestIsActive_RecentlyDeployedFastPath checks that a contract whose deploy
// block is at or above fromBlock is immediately marked active — no eth_getLogs
// call needed.
func TestIsActive_RecentlyDeployedFastPath(t *testing.T) {
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
		minDays     = 30
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	// deployBlock is very close to the tip — definitely within 30 days.
	deployBlock := latestBlock - 100

	handler, _ := syntheticChain(t, genesisTS, latestBlock, blockSecs, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	result, err := checker.IsActive(context.Background(), testAddress, deployBlock, minDays)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true for recently deployed contract, got false; reason: %s", result.Reason)
	}
	// When the deploy-block fast-path fires, no logs are queried.
	if result.LogsFound != 0 {
		t.Errorf("expected LogsFound=0 when deploy block is within window, got %d", result.LogsFound)
	}
}

// TestIsActive_OldDeployNoLogs verifies that an old contract with no recent
// logs is marked inactive.
func TestIsActive_OldDeployNoLogs(t *testing.T) {
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
		minDays     = 30
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	// deployBlock is very early in the chain — well outside the 30-day window.
	deployBlock := uint64(1)

	handler, _ := syntheticChain(t, genesisTS, latestBlock, blockSecs, []any{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	result, err := checker.IsActive(context.Background(), testAddress, deployBlock, minDays)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Active {
		t.Errorf("expected Active=false for old contract with no logs, got true; reason: %s", result.Reason)
	}
}

// TestIsActive_OldDeployWithRecentLogs verifies that an old contract that has
// emitted recent logs is marked active.
func TestIsActive_OldDeployWithRecentLogs(t *testing.T) {
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
		minDays     = 30
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	deployBlock := uint64(1) // old deployment

	recentLogs := []map[string]string{
		{"transactionHash": "0xaaa"},
		{"transactionHash": "0xbbb"},
	}
	handler, _ := syntheticChain(t, genesisTS, latestBlock, blockSecs, recentLogs)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	result, err := checker.IsActive(context.Background(), testAddress, deployBlock, minDays)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true for old contract with recent logs, got false; reason: %s", result.Reason)
	}
	if result.LogsFound != 2 {
		t.Errorf("expected LogsFound=2, got %d", result.LogsFound)
	}
}

// TestIsActive_UnknownDeployBlock checks the path where the deployment block is
// unknown (0) — only the eth_getLogs check is performed.
func TestIsActive_UnknownDeployBlock(t *testing.T) {
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
		minDays     = 30
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	recentLogs := []map[string]string{{"transactionHash": "0x111"}}
	handler, _ := syntheticChain(t, genesisTS, latestBlock, blockSecs, recentLogs)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	// deployBlock=0 → unknown, must fall through to eth_getLogs.
	result, err := checker.IsActive(context.Background(), testAddress, 0, minDays)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true when logs found and deploy block unknown, got false; reason: %s", result.Reason)
	}
}

// TestIsActive_UnknownDeployBlock_NoLogs checks that unknown deploy block +
// no logs → inactive.
func TestIsActive_UnknownDeployBlock_NoLogs(t *testing.T) {
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
		minDays     = 30
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	handler, _ := syntheticChain(t, genesisTS, latestBlock, blockSecs, []any{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	result, err := checker.IsActive(context.Background(), testAddress, 0, minDays)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Active {
		t.Errorf("expected Active=false with unknown deploy block and no logs, got true; reason: %s", result.Reason)
	}
}

// TestIsActive_GetBlockError checks that an error from eth_getBlockByNumber is
// propagated as a non-nil error return.
func TestIsActive_GetBlockError(t *testing.T) {
	h := newRPCHandler()
	h.errors["eth_getBlockByNumber"] = &rpcError{Code: -32603, Message: "internal error"}
	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	_, err := checker.IsActive(context.Background(), testAddress, 1, 30)
	if err == nil {
		t.Fatal("expected error from getLatestBlock, got nil")
	}
}

// TestIsActive_GetLogsError checks that a failing eth_getLogs call results in
// Active=false (conservative non-fatal path) rather than a returned error.
func TestIsActive_GetLogsError(t *testing.T) {
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
		minDays     = 30
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	// Use a real synthetic-chain handler for block calls but inject a getLogs error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var resp map[string]any
		switch req.Method {
		case "eth_getBlockByNumber":
			blockRef, _ := req.Params[0].(string)
			var n uint64
			if blockRef == "latest" {
				n = latestBlock
			} else {
				n, _ = hexToUint64(blockRef)
			}
			resp = map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": blockResponse(n, genesisTS+n*blockSecs),
			}
		case "eth_getLogs":
			resp = map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"error": &rpcError{Code: -32005, Message: "query returned more than 10000 results"},
			}
		default:
			http.Error(w, "method not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	// Old deploy block so we don't hit the fast path.
	result, err := checker.IsActive(context.Background(), testAddress, 1, minDays)
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
	const (
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	handler, _ := syntheticChain(t, genesisTS, latestBlock, blockSecs, []any{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	// Old deploy block + no logs → inactive regardless of which default is used.
	result, err := checker.IsActive(context.Background(), testAddress, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Active {
		t.Errorf("expected Active=false with default window and no logs, got true; reason: %s", result.Reason)
	}
}

// TestIsActive_BisectFromBlock verifies that the binary search converges on the
// correct fromBlock using a synthetic chain where timestamp(N) = genesisTS + N*blockSecs.
// The expected fromBlock is exactly derivable from the cutoff without knowing avg block time.
func TestIsActive_BisectFromBlock(t *testing.T) {
	const (
		minDays     = 7
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
	)

	// Anchor latest block at now so the chain clearly extends past any cutoff.
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	cutoffUnix := uint64(time.Now().UTC().AddDate(0, 0, -minDays).Unix())
	// timestamp(N) = genesisTS + N*blockSecs  =>  N = (cutoffUnix - genesisTS) / blockSecs
	// Round up to get the first block >= cutoff.
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
			blockRef, _ := req.Params[0].(string)
			var n uint64
			if blockRef == "latest" {
				n = latestBlock
			} else {
				n, _ = hexToUint64(blockRef)
			}
			result = blockResponse(n, genesisTS+n*blockSecs)

		case "eth_getLogs":
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

	// deployBlock=0 (unknown) so we always reach eth_getLogs.
	if latestTS <= cutoffUnix {
		t.Fatalf("test setup broken: latestTS %d <= cutoffUnix %d", latestTS, cutoffUnix)
	}

	_, err := checker.IsActive(context.Background(), testAddress, 0, minDays)
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

// TestIsActive_LowBlockNumber verifies that fromBlock is clamped correctly when
// the entire chain history is within the look-back window.
func TestIsActive_LowBlockNumber(t *testing.T) {
	const (
		chainHeight = uint64(100)
		blockSecs   = uint64(12)
		minDays     = 30
	)

	// All blocks have an old timestamp so the chain predates the cutoff entirely.
	// Use genesisTS 2 years ago; latestTS = genesisTS + 100*12 is still old.
	genesisTS := uint64(time.Now().UTC().AddDate(-2, 0, 0).Unix())

	// But latestTS must be > cutoffUnix to avoid the "entire chain in window"
	// early return. We achieve this by using nowTS() for the latest block only,
	// while bisection calls get the old timestamp.
	var capturedFromBlock uint64
	captured := false

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
				result = blockResponse(chainHeight, nowTS())
			} else {
				n, _ := hexToUint64(blockRef)
				result = blockResponse(n, genesisTS+n*blockSecs)
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

	_, err := checker.IsActive(context.Background(), testAddress, 0, minDays)
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
// timestamp is at or before the cutoff (entire chain is "older" than the
// window) the function returns Active=true immediately without calling eth_getLogs.
func TestIsActive_LatestWithinWindow(t *testing.T) {
	h := newRPCHandler()
	// Latest block timestamp is 2 years in the past — older than any window.
	oldBlockTS := uint64(time.Now().UTC().AddDate(-2, 0, 0).Unix())
	h.responses["eth_getBlockByNumber"] = blockResponse(10, oldBlockTS)
	// eth_getLogs must NOT be called.

	checker, srv := newCheckerWithHandler(h)
	defer srv.Close()

	result, err := checker.IsActive(context.Background(), testAddress, 0, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Errorf("expected Active=true when latest block timestamp predates the window, got false; reason: %s", result.Reason)
	}
	for _, call := range h.calls {
		if call == "eth_getLogs" {
			t.Error("eth_getLogs should not have been called in the early-return path")
		}
	}
}

// TestIsActive_HTTPError checks that a non-200 HTTP response is propagated as
// an error from IsActive.
func TestIsActive_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	_, err := checker.IsActive(context.Background(), testAddress, 1, 30)
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
	cancel()

	_, err := checker.IsActive(ctx, testAddress, 1, 30)
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
		tc := tc
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

// TestNewActivityChecker_Defaults verifies that a nil HTTP client is replaced
// with a working default.
func TestNewActivityChecker_Defaults(t *testing.T) {
	checker := NewActivityChecker("http://localhost:8545", nil, newTestLogger())
	if checker.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
}

// TestIsActive_BisectionCachedAcrossCalls verifies that bisection RPC calls
// (numbered eth_getBlockByNumber) are made only once regardless of how many
// times IsActive is called on the same checker within the same day.
func TestIsActive_BisectionCachedAcrossCalls(t *testing.T) {
	const (
		minDays     = 7
		blockSecs   = uint64(12)
		latestBlock = uint64(10_000_000)
	)
	latestTS := nowTS()
	genesisTS := latestTS - latestBlock*blockSecs

	handler, bisectCalls := syntheticChain(t, genesisTS, latestBlock, blockSecs, []any{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	checker := NewActivityChecker(srv.URL, srv.Client(), newTestLogger())

	const numCalls = 5
	for i := range numCalls {
		result, err := checker.IsActive(context.Background(), testAddress, 0, minDays)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if result.Active {
			t.Errorf("call %d: expected Active=false (no logs), got true; reason: %s", i, result.Reason)
		}
	}

	if *bisectCalls == 0 {
		t.Error("expected bisection calls on the first IsActive invocation, got none")
	}
	bisectCallsAfterFirst := *bisectCalls

	// A second batch must not trigger any additional bisection calls.
	for i := range numCalls {
		_, err := checker.IsActive(context.Background(), testAddress, 0, minDays)
		if err != nil {
			t.Fatalf("second batch call %d: unexpected error: %v", i, err)
		}
	}
	if *bisectCalls != bisectCallsAfterFirst {
		t.Errorf("bisection ran again after cache was populated: before=%d after=%d",
			bisectCallsAfterFirst, *bisectCalls)
	}
}
