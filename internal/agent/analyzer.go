package agent

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/julienrbrt/bim/internal/analyzer"
	"github.com/julienrbrt/bim/internal/config"
	"github.com/julienrbrt/bim/internal/sourcify"
	"github.com/julienrbrt/bim/internal/store"
)

// addressPattern matches Ethereum addresses (0x + 40 hex chars) in source code.
var addressPattern = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)

// interestingVarPattern matches state variable or immutable declarations whose
// name suggests they point to a protocol contract worth fetching.
var interestingVarPattern = regexp.MustCompile(
	`(?i)\b(?:address|I[A-Z]\w+)\s+(?:(?:public|private|internal|external|immutable|constant)\s+)*` +
		`(\w*(?:oracle|pool|router|factory|vault|token|pair|feed|registry|controller|manager|lend|borrow|swap|bridge|staking|reward|price|market)\w*)\b`,
)

// AnalyzerTool fetches verified contract source code from Sourcify and runs
// LLM-powered security analysis, persisting results in the store.
type AnalyzerTool struct {
	analyzer *analyzer.Analyzer
	sourcify *sourcify.Client
	store    store.Store
	cfg      *config.Config
	logger   *slog.Logger
}

func NewAnalyzerTool(
	az *analyzer.Analyzer,
	sourcifyClient *sourcify.Client,
	st store.Store,
	logger *slog.Logger,
	cfg *config.Config,
) *AnalyzerTool {
	return &AnalyzerTool{
		analyzer: az,
		sourcify: sourcifyClient,
		store:    st,
		cfg:      cfg,
		logger:   logger,
	}
}

// AnalyzeResult holds the output of an analysis run exposed to the agent layer.
type AnalyzeResult struct {
	AnalysisID    string             `json:"analysisId"`
	ChainID       uint64             `json:"chainId"`
	Address       string             `json:"address"`
	ContractName  string             `json:"contractName"`
	Language      string             `json:"language"`
	TotalFindings int                `json:"totalFindings"`
	CriticalCount int                `json:"criticalCount"`
	HighCount     int                `json:"highCount"`
	MediumCount   int                `json:"mediumCount"`
	LowCount      int                `json:"lowCount"`
	InfoCount     int                `json:"infoCount"`
	Findings      []analyzer.Finding `json:"findings"`
	Summary       string             `json:"summary"`
	Error         string             `json:"error,omitempty"`
}

func (r *AnalyzeResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("Analysis failed for %s on chain %d: %s", r.Address, r.ChainID, r.Error)
	}
	return r.Summary
}

// Analyze runs the full security analysis pipeline for a single contract.
func (t *AnalyzerTool) Analyze(ctx context.Context, chainID uint64, address string) (*AnalyzeResult, error) {
	address = normalizeAddress(address)

	t.logger.Info("starting contract analysis",
		"chain_id", chainID,
		"address", address,
	)

	result := &AnalyzeResult{
		ChainID: chainID,
		Address: address,
	}

	if err := t.store.UpdateContractStatus(ctx, chainID, address, store.StatusAnalyzing, ""); err != nil {
		t.logger.Warn("failed to update contract status to analyzing",
			"chain_id", chainID,
			"address", address,
			"error", err,
		)
	}

	contract, err := t.sourcify.GetContract(ctx, chainID, address)
	if err != nil {
		errMsg := fmt.Sprintf("failed to fetch source from Sourcify: %v", err)
		result.Error = errMsg
		t.markFailed(ctx, chainID, address, errMsg)
		return result, fmt.Errorf("fetching contract source: %w", err)
	}

	if len(contract.Sources) == 0 {
		errMsg := "contract has no source files on Sourcify"
		result.Error = errMsg
		t.markFailed(ctx, chainID, address, errMsg)
		return result, fmt.Errorf("%s", errMsg)
	}

	sources := make(map[string]string, len(contract.Sources))
	for path, src := range contract.Sources {
		sources[path] = src.Content
	}

	var language, compilerVersion, contractName string
	if contract.Compilation != nil {
		language = contract.Compilation.Language
		compilerVersion = contract.Compilation.CompilerVersion
		contractName = contract.Compilation.FullyQualifiedName
	}

	if skipped, matchedEntry := t.cfg.IsContractSkipped(contractName); skipped {
		t.logger.Info("skipping whitelisted contract",
			"chain_id", chainID,
			"address", address,
			"contract", contractName,
			"matched_entry", matchedEntry,
		)
		skipMsg := fmt.Sprintf("contract matches skipped entry %q", matchedEntry)
		if err := t.store.UpdateContractStatus(ctx, chainID, address, store.StatusSkipped, skipMsg); err != nil {
			t.logger.Warn("failed to mark contract as skipped",
				"chain_id", chainID,
				"address", address,
				"error", err,
			)
		}
		result.ContractName = contractName
		result.Language = language
		result.Summary = fmt.Sprintf("Contract %s skipped: matches whitelist entry %q.", contractName, matchedEntry)
		return result, nil
	}

	external := t.resolveExternalContracts(ctx, chainID, sources, contract.ProxyResolution)

	input := analyzer.AnalysisInput{
		ChainID:           chainID,
		Address:           address,
		Sources:           sources,
		Language:          language,
		CompilerVersion:   compilerVersion,
		ContractName:      contractName,
		ExternalContracts: external,
	}

	result.ContractName = input.ContractName
	result.Language = input.Language

	analysisResult, err := t.analyzer.Analyze(ctx, input)
	if err != nil {
		errMsg := fmt.Sprintf("analysis failed: %v", err)
		result.Error = errMsg
		t.markFailed(ctx, chainID, address, errMsg)
		return result, fmt.Errorf("running analysis: %w", err)
	}

	result.AnalysisID = analysisResult.ID
	result.TotalFindings = len(analysisResult.Findings)
	result.Findings = analysisResult.Findings

	for _, f := range analysisResult.Findings {
		switch f.Severity {
		case analyzer.SeverityCritical:
			result.CriticalCount++
		case analyzer.SeverityHigh:
			result.HighCount++
		case analyzer.SeverityMedium:
			result.MediumCount++
		case analyzer.SeverityLow:
			result.LowCount++
		case analyzer.SeverityInfo:
			result.InfoCount++
		}
	}

	result.Summary = t.buildSummary(result, analysisResult)

	if err := t.store.SaveAnalysisResult(ctx, analysisResult); err != nil {
		t.logger.Error("failed to persist analysis result",
			"analysis_id", analysisResult.ID,
			"error", err,
		)
	}

	t.logger.Info("contract analysis complete",
		"analysis_id", analysisResult.ID,
		"chain_id", chainID,
		"address", address,
		"total_findings", result.TotalFindings,
		"critical", result.CriticalCount,
		"high", result.HighCount,
		"duration", analysisResult.Duration,
	)

	return result, nil
}

// PendingContracts returns the list of contracts with status "pending".
func (t *AnalyzerTool) PendingContracts(ctx context.Context) ([]store.Contract, error) {
	return t.store.ListContracts(ctx, store.ContractFilter{
		Status: store.StatusPending,
	})
}

// AnalyzePending fetches all contracts with status "pending" and runs analysis on each.
func (t *AnalyzerTool) AnalyzePending(ctx context.Context) ([]*AnalyzeResult, error) {
	contracts, err := t.PendingContracts(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pending contracts: %w", err)
	}

	t.logger.Info("analyzing pending contracts", "count", len(contracts))

	var results []*AnalyzeResult
	for _, c := range contracts {
		if ctx.Err() != nil {
			break
		}

		result, err := t.Analyze(ctx, c.ChainID, c.Address)
		if err != nil {
			t.logger.Error("analysis failed for pending contract",
				"chain_id", c.ChainID,
				"address", c.Address,
				"error", err,
			)
		}
		results = append(results, result)
	}

	return results, nil
}

// ReAnalyze forces a re-analysis by resetting the contract status first.
func (t *AnalyzerTool) ReAnalyze(ctx context.Context, chainID uint64, address string) (*AnalyzeResult, error) {
	address = normalizeAddress(address)

	t.logger.Info("re-analyzing contract",
		"chain_id", chainID,
		"address", address,
	)

	if err := t.store.UpdateContractStatus(ctx, chainID, address, store.StatusPending, ""); err != nil {
		t.logger.Warn("failed to reset contract status for re-analysis",
			"chain_id", chainID,
			"address", address,
			"error", err,
		)
	}

	return t.Analyze(ctx, chainID, address)
}

func (t *AnalyzerTool) buildSummary(result *AnalyzeResult, analysis *analyzer.AnalysisResult) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"Security analysis of %s (%s) on %s completed in %s.\n",
		result.ContractName,
		result.Address,
		t.cfg.ChainName(result.ChainID),
		analysis.Duration.Round(time.Second),
	)

	actionable := analysis.CriticalAndHighFindings()
	if len(actionable) > 0 {
		fmt.Fprintf(&b,
			"Found %d CRITICAL fund-theft vulnerabilities exploitable by a third-party attacker:\n",
			len(actionable),
		)
		for i, f := range actionable {
			fmt.Fprintf(&b, "  %d. %s — %s (confidence: %.0f%%)\n",
				i+1, f.Title, f.AffectedFunction, f.Confidence*100)
			if f.Impact != "" {
				fmt.Fprintf(&b, "     Impact: %s\n", f.Impact)
			}
		}
	} else {
		b.WriteString("No critical fund-theft vulnerabilities found. The contract appears safe from third-party exploits.")
	}

	if analysis.Summary.Description != "" {
		fmt.Fprintf(&b, "\nContract summary: %s", analysis.Summary.Description)
	}

	return b.String()
}

func (t *AnalyzerTool) markFailed(ctx context.Context, chainID uint64, address, errMsg string) {
	if err := t.store.UpdateContractStatus(ctx, chainID, address, store.StatusFailed, errMsg); err != nil {
		t.logger.Error("failed to mark contract as failed",
			"chain_id", chainID,
			"address", address,
			"error", err,
		)
	}
}

// resolveExternalContracts attempts to fetch Sourcify-verified source code for
// contracts that the analyzed contract interacts with. Two sources are used:
//
//  1. Sourcify's ProxyResolution field — the implementation address is always
//     relevant when the contract is a proxy.
//  2. Hardcoded addresses in the source that are assigned to state variables
//     whose names suggest a protocol role (oracle, pool, router, etc.).
//
// Fetches are best-effort: failures are logged and silently skipped so they
// never block the main analysis.
func (t *AnalyzerTool) resolveExternalContracts(
	ctx context.Context,
	chainID uint64,
	sources map[string]string,
	proxy *sourcify.ProxyResolution,
) []analyzer.ExternalContract {
	// Collect candidate (address, role, name) tuples, deduplicating by address.
	type candidate struct {
		role string
		name string
	}
	seen := make(map[string]candidate)

	// 1. Proxy implementations reported by Sourcify.
	if proxy != nil && proxy.IsProxy {
		for _, impl := range proxy.Implementations {
			addr := normalizeAddress(impl.Address)
			if addr != "" {
				seen[addr] = candidate{role: "proxy implementation", name: impl.Name}
			}
		}
	}

	// 2. Hardcoded addresses assigned to protocol-role variables in source.
	for _, content := range sources {
		for _, match := range interestingVarPattern.FindAllStringSubmatch(content, -1) {
			varName := match[1]
			// Find an address literal on the same or nearby line.
			// We search within a small window around the variable name occurrence.
			idx := strings.Index(content, match[0])
			if idx < 0 {
				continue
			}
			window := content[idx:]
			// Take just enough text to cover a typical assignment line.
			if len(window) > 300 {
				window = window[:300]
			}
			for _, addr := range addressPattern.FindAllString(window, -1) {
				addr = normalizeAddress(addr)
				if addr == "" {
					continue
				}
				if _, already := seen[addr]; !already {
					seen[addr] = candidate{role: varName, name: ""}
				}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	var external []analyzer.ExternalContract
	for addr, cand := range seen {
		contract, err := t.sourcify.GetContract(ctx, chainID, addr)
		if err != nil {
			// Not verified on Sourcify or network error — skip silently.
			t.logger.Debug("external contract not available on sourcify",
				"address", addr,
				"role", cand.role,
				"error", err,
			)
			continue
		}
		if len(contract.Sources) == 0 {
			continue
		}

		name := cand.name
		if name == "" && contract.Compilation != nil {
			name = contract.Compilation.Name
		}

		srcs := make(map[string]string, len(contract.Sources))
		for path, src := range contract.Sources {
			srcs[path] = src.Content
		}

		t.logger.Info("resolved external contract",
			"address", addr,
			"name", name,
			"role", cand.role,
			"source_files", len(srcs),
		)

		external = append(external, analyzer.ExternalContract{
			Address: addr,
			Name:    name,
			Role:    cand.role,
			Sources: srcs,
		})
	}

	return external
}
