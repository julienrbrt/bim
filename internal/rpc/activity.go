// Package rpc provides lightweight Ethereum JSON-RPC helpers for BiM.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// defaultTimeout is the HTTP timeout for a single RPC call.
	defaultTimeout = 15 * time.Second

	// defaultMinAgeDays is the default number of days a contract must have been
	// active (or recently deployed) to be considered worth analyzing.
	defaultMinAgeDays = 30

	// maxBisectSteps caps the binary-search loop so it always terminates in
	// O(log n) steps regardless of chain height.
	maxBisectSteps = 64

	// noDeployBlock is the sentinel value meaning the deployment block is unknown.
	noDeployBlock = uint64(0)
)

// ActivityChecker queries an Ethereum JSON-RPC endpoint to determine whether a
// contract has seen recent on-chain activity (emitted events) within a
// configurable look-back window.
type ActivityChecker struct {
	rpcURL     string
	httpClient *http.Client
	logger     *slog.Logger

	// fromBlock cache — keyed by minDays, invalidated when the date changes.
	cacheMu         sync.Mutex
	cachedFromBlock uint64
	cacheMinDays    int
	cacheDate       string // "YYYY-MM-DD" in UTC
}

// ActivityResult is returned by IsActive.
type ActivityResult struct {
	// Active is true when the contract satisfies the recency requirement.
	Active bool
	// Reason is a short human-readable explanation of the decision.
	Reason string
	// DeployBlock is the on-chain deployment block number, if known.
	DeployBlock uint64
	// LatestBlock is the block number sampled during the check.
	LatestBlock uint64
	// LogsFound is the number of logs emitted by the contract within the window.
	LogsFound int
}

// NewActivityChecker creates an ActivityChecker for the given JSON-RPC URL.
func NewActivityChecker(rpcURL string, httpClient *http.Client, logger *slog.Logger) *ActivityChecker {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &ActivityChecker{
		rpcURL:     rpcURL,
		httpClient: httpClient,
		logger:     logger,
	}
}

// IsActive reports whether the contract at address was active within the last
// minDays days, using its on-chain deployment block and recent event logs.
//
// deployBlock should be the block number at which the contract was deployed
// (from Sourcify's Deployment.BlockNumber). Pass noDeployBlock (0) when
// unknown; in that case only the eth_getLogs check is performed.
//
// A contract is considered active when any of the following hold:
//   - Its deployment block is at or above the cached fromBlock for the window
//     (i.e. it was deployed within the last minDays days).
//   - It emitted at least one log within the last minDays of blocks.
func (c *ActivityChecker) IsActive(ctx context.Context, address string, deployBlock uint64, minDays int) (*ActivityResult, error) {
	if minDays <= 0 {
		minDays = defaultMinAgeDays
	}

	result := &ActivityResult{DeployBlock: deployBlock}

	// Fetch the latest block to anchor the look-back window.
	cutoff := time.Now().UTC().AddDate(0, 0, -minDays)
	latestBlock, latestTimestamp, err := c.getBlockByTag(ctx, "latest")
	if err != nil {
		return nil, fmt.Errorf("rpc eth_getBlockByNumber(latest): %w", err)
	}
	result.LatestBlock = latestBlock

	cutoffUnix := uint64(cutoff.Unix())

	// If the latest block itself predates the cutoff (e.g. a very new chain or
	// a test environment), treat the whole chain as within the window.
	if latestTimestamp <= cutoffUnix {
		result.Active = true
		result.Reason = fmt.Sprintf("latest block timestamp is within the %d-day window", minDays)
		return result, nil
	}

	// Binary-search for the earliest block whose timestamp >= cutoffUnix.
	// The result is cached per (minDays, calendar date) so the O(log n) RPC
	// calls are made at most once per day, not once per contract.
	fromBlock, err := c.fromBlockCached(ctx, cutoffUnix, 0, latestBlock, minDays)
	if err != nil {
		// Non-fatal: fall back to fromBlock=0.
		c.logger.Warn("block bisection failed, falling back to fromBlock=0",
			"address", address,
			"error", err,
		)
		fromBlock = 0
	}

	// Fast path: contract was deployed within the look-back window — no need
	// to query logs. deployBlock==0 is the "unknown" sentinel so we skip it.
	if deployBlock != noDeployBlock && deployBlock >= fromBlock {
		result.Active = true
		result.Reason = fmt.Sprintf("contract deployed at block %d, within the %d-day window (from block %d)",
			deployBlock, minDays, fromBlock)
		c.logger.Debug("contract is active (recently deployed)",
			"address", address,
			"deploy_block", deployBlock,
			"from_block", fromBlock,
		)
		return result, nil
	}
	c.logger.Debug("checking contract activity via eth_getLogs",
		"address", address,
		"from_block", fromBlock,
		"to_block", latestBlock,
		"window_days", minDays,
	)

	logCount, err := c.getLogCount(ctx, address, fromBlock, latestBlock)
	if err != nil {
		// Non-fatal: if getLogs fails we conservatively treat the contract as
		// inactive rather than propagating the error and blocking the pipeline.
		c.logger.Warn("eth_getLogs failed, treating contract as inactive",
			"address", address,
			"error", err,
		)
		result.Active = false
		result.Reason = fmt.Sprintf("eth_getLogs failed (%v); contract treated as inactive", err)
		return result, nil
	}

	result.LogsFound = logCount

	if logCount > 0 {
		result.Active = true
		result.Reason = fmt.Sprintf("contract emitted %d log(s) in the last %d days (from block %d)",
			logCount, minDays, fromBlock)
		c.logger.Debug("contract is active (recent logs)",
			"address", address,
			"logs", logCount,
			"from_block", fromBlock,
		)
		return result, nil
	}

	result.Active = false
	if deployBlock == noDeployBlock {
		result.Reason = fmt.Sprintf("no logs emitted in the last %d days and deployment block unknown", minDays)
	} else {
		result.Reason = fmt.Sprintf("no logs emitted in the last %d days; deployed at block %d (before the %d-day window starting at block %d)",
			minDays, deployBlock, minDays, fromBlock)
	}

	c.logger.Debug("contract is inactive",
		"address", address,
		"logs", logCount,
		"deploy_block", deployBlock,
		"from_block", fromBlock,
	)

	return result, nil
}

// fromBlockCached returns the bisected fromBlock for the given cutoffUnix and
// minDays, reusing the cached value when the calendar date (UTC) has not
// changed since the last bisection. This means the O(log n) bisection RPC
// calls are made at most once per day per ActivityChecker instance, regardless
// of how many contracts are checked.
func (c *ActivityChecker) fromBlockCached(ctx context.Context, cutoffUnix uint64, lo, hi uint64, minDays int) (uint64, error) {
	today := time.Now().UTC().Format("2006-01-02")

	c.cacheMu.Lock()
	if c.cacheDate == today && c.cacheMinDays == minDays {
		cached := c.cachedFromBlock
		c.cacheMu.Unlock()
		c.logger.Debug("reusing cached fromBlock", "from_block", cached, "date", today, "min_days", minDays)
		return cached, nil
	}
	c.cacheMu.Unlock()

	// Cache miss — run the bisection.
	fromBlock, err := c.bisectFromBlock(ctx, cutoffUnix, lo, hi)
	if err != nil {
		return 0, err
	}

	c.cacheMu.Lock()
	c.cachedFromBlock = fromBlock
	c.cacheMinDays = minDays
	c.cacheDate = today
	c.cacheMu.Unlock()

	c.logger.Debug("cached fromBlock after bisection", "from_block", fromBlock, "date", today, "min_days", minDays)
	return fromBlock, nil
}

// bisectFromBlock returns the lowest block number in [lo, hi] whose timestamp
// is >= cutoffUnix. It uses at most maxBisectSteps calls to eth_getBlockByNumber.
// If lo's timestamp is already >= cutoffUnix it returns lo immediately (0 calls).
func (c *ActivityChecker) bisectFromBlock(ctx context.Context, cutoffUnix, lo, hi uint64) (uint64, error) {
	// If the entire range is within the window just return lo.
	_, loTS, err := c.getBlockByNumber(ctx, lo)
	if err != nil {
		return 0, fmt.Errorf("getBlockByNumber(%d): %w", lo, err)
	}
	if loTS >= cutoffUnix {
		return lo, nil
	}

	result := hi // conservative default: scan the full window if bisection yields nothing

	for step := 0; step < maxBisectSteps && lo < hi; step++ {
		mid := lo + (hi-lo)/2
		_, midTS, err := c.getBlockByNumber(ctx, mid)
		if err != nil {
			return 0, fmt.Errorf("getBlockByNumber(%d): %w", mid, err)
		}

		if midTS >= cutoffUnix {
			result = mid
			hi = mid
		} else {
			lo = mid + 1
		}
	}

	return result, nil
}

// ---- JSON-RPC helpers -------------------------------------------------------

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

func (c *ActivityChecker) call(ctx context.Context, method string, params []any, out any) error {
	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	if rpcResp.Error != nil {
		return rpcResp.Error
	}

	if out != nil {
		if err := json.Unmarshal(rpcResp.Result, out); err != nil {
			return fmt.Errorf("decoding result: %w", err)
		}
	}
	return nil
}

// getBlockByTag fetches a block by tag ("latest", "earliest", etc.) and
// returns its number and UNIX timestamp.
func (c *ActivityChecker) getBlockByTag(ctx context.Context, tag string) (number uint64, timestamp uint64, err error) {
	return c.fetchBlock(ctx, tag)
}

// getBlockByNumber fetches a block by number and returns its number and UNIX
// timestamp.
func (c *ActivityChecker) getBlockByNumber(ctx context.Context, n uint64) (number uint64, timestamp uint64, err error) {
	return c.fetchBlock(ctx, "0x"+strconv.FormatUint(n, 16))
}

// fetchBlock is the shared implementation for getBlockByTag / getBlockByNumber.
func (c *ActivityChecker) fetchBlock(ctx context.Context, blockRef string) (number uint64, timestamp uint64, err error) {
	var block struct {
		Number    string `json:"number"`
		Timestamp string `json:"timestamp"`
	}
	if err := c.call(ctx, "eth_getBlockByNumber", []any{blockRef, false}, &block); err != nil {
		return 0, 0, err
	}
	number, err = hexToUint64(block.Number)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing block number %q: %w", block.Number, err)
	}
	timestamp, err = hexToUint64(block.Timestamp)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing block timestamp %q: %w", block.Timestamp, err)
	}
	return number, timestamp, nil
}

// getLogCount returns the number of logs emitted by address in [fromBlock, toBlock].
func (c *ActivityChecker) getLogCount(ctx context.Context, address string, fromBlock, toBlock uint64) (int, error) {
	filter := map[string]any{
		"fromBlock": "0x" + strconv.FormatUint(fromBlock, 16),
		"toBlock":   "0x" + strconv.FormatUint(toBlock, 16),
		"address":   strings.ToLower(address),
	}

	var logs []json.RawMessage
	if err := c.call(ctx, "eth_getLogs", []any{filter}, &logs); err != nil {
		return 0, err
	}
	return len(logs), nil
}

// hexToUint64 converts a 0x-prefixed hex string to uint64.
func hexToUint64(s string) (uint64, error) {
	return ParseUint64Hex(s)
}

// ParseUint64Hex converts a 0x-prefixed hex string to uint64.
// It is exported so callers that parse Sourcify/RPC block numbers can reuse it
// without importing a separate strconv dependency.
func ParseUint64Hex(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 16, 64)
}
