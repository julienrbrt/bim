// Package agent defines the ADK tools and orchestrator for BiM.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/julienrbrt/bim/internal/analyzer"
	"github.com/julienrbrt/bim/internal/config"
	"github.com/julienrbrt/bim/internal/store"
)

// Orchestrator coordinates the discovery, analysis, and reporting pipeline.
// It composes DiscoveryTool, AnalyzerTool, and ReporterTool and exposes
// high-level methods that the ADK agent in main.go registers as tool functions.
type Orchestrator struct {
	discovery *DiscoveryTool
	analyzer  *AnalyzerTool
	reporter  *ReporterTool
	cfg       *config.Config
	logger    *slog.Logger
}

func NewOrchestrator(
	discovery *DiscoveryTool,
	analyzer *AnalyzerTool,
	reporter *ReporterTool,
	logger *slog.Logger,
	cfg *config.Config,
) *Orchestrator {
	return &Orchestrator{
		discovery: discovery,
		analyzer:  analyzer,
		reporter:  reporter,
		cfg:       cfg,
		logger:    logger,
	}
}

// PipelineResult holds the combined output of a full pipeline run.
type PipelineResult struct {
	// Discovery is the result of the contract discovery phase.
	Discovery *DiscoverResult `json:"discovery,omitempty"`
	// Analyses holds the results of the analysis phase.
	Analyses []*AnalyzeResult `json:"analyses,omitempty"`
	// Reports holds the results of the reporting phase.
	Reports []*ReportResult `json:"reports,omitempty"`
	// Duration is the total time the pipeline took.
	Duration time.Duration `json:"duration"`
	// Summary is a human-readable summary of the entire run.
	Summary string `json:"summary"`
}

func (r *PipelineResult) String() string { return r.Summary }

// RunFullPipeline executes discover → analyze → report in sequence.
// Each contract is fully processed (analyze + report) before moving to the next
// so that reports are written as soon as actionable findings are found.
func (o *Orchestrator) RunFullPipeline(ctx context.Context) (*PipelineResult, error) {
	start := time.Now()
	o.logger.Info("starting full pipeline run")

	result := &PipelineResult{}

	o.logger.Info("pipeline phase 1: discovery")
	discoverResult, err := o.discovery.Discover(ctx)
	if err != nil {
		o.logger.Error("discovery phase failed", "error", err)
	}
	result.Discovery = discoverResult

	if ctx.Err() != nil {
		result.Duration = time.Since(start)
		result.Summary = "Pipeline interrupted during discovery phase."
		return result, ctx.Err()
	}

	o.logger.Info("pipeline phase 2: analyze and report")
	pending, err := o.analyzer.PendingContracts(ctx)
	if err != nil {
		o.logger.Error("failed to list pending contracts", "error", err)
	}

	for _, c := range pending {
		if ctx.Err() != nil {
			break
		}

		ar, err := o.analyzer.Analyze(ctx, c.ChainID, c.Address)
		if err != nil {
			o.logger.Error("analysis failed",
				"chain_id", c.ChainID, "address", c.Address, "error", err,
			)
		}
		result.Analyses = append(result.Analyses, ar)

		if ar.Error != "" {
			continue
		}

		reports := o.reportActionableFindings(ctx, ar)
		result.Reports = append(result.Reports, reports...)
	}

	// Sweep: generate reports for any previously unreported actionable findings
	// (e.g. from interrupted earlier runs or manual analyze_contract calls).
	if ctx.Err() == nil {
		orphaned, err := o.reporter.GenerateAllPending(ctx)
		if err != nil {
			o.logger.Error("failed to generate reports for orphaned findings", "error", err)
		}
		if len(orphaned) > 0 {
			o.logger.Info("generated reports for previously unreported findings", "count", len(orphaned))
			result.Reports = append(result.Reports, orphaned...)
		}
	}

	result.Duration = time.Since(start)
	result.Summary = o.buildPipelineSummary(result)

	o.logger.Info("pipeline run complete",
		"duration", result.Duration,
		"new_contracts", countNewContracts(result.Discovery),
		"analyses", len(result.Analyses),
		"reports", len(result.Reports),
	)

	return result, nil
}

// RunDiscovery executes only the discovery phase.
func (o *Orchestrator) RunDiscovery(ctx context.Context) (*DiscoverResult, error) {
	o.logger.Info("running discovery phase only")
	return o.discovery.Discover(ctx)
}

// RunAnalysis executes only the analysis phase on all pending contracts.
func (o *Orchestrator) RunAnalysis(ctx context.Context) ([]*AnalyzeResult, error) {
	o.logger.Info("running analysis phase only")
	return o.analyzer.AnalyzePending(ctx)
}

// RunReporting generates reports for all unreported actionable findings.
func (o *Orchestrator) RunReporting(ctx context.Context) ([]*ReportResult, error) {
	o.logger.Info("running reporting phase only")
	return o.reporter.GenerateAllPending(ctx)
}

// ProcessContract runs discover → analyze → report for a single contract.
func (o *Orchestrator) ProcessContract(ctx context.Context, chainID uint64, address string) (*PipelineResult, error) {
	start := time.Now()
	address = normalizeAddress(address)

	o.logger.Info("processing single contract", "chain_id", chainID, "address", address)

	result := &PipelineResult{}

	contract, err := o.discovery.DiscoverSingleContract(ctx, chainID, address)
	if err != nil {
		result.Duration = time.Since(start)
		result.Summary = fmt.Sprintf("Failed to discover contract %s on chain %d: %v", address, chainID, err)
		return result, err
	}

	o.logger.Info("contract discovered/retrieved",
		"chain_id", chainID, "address", address,
		"name", contract.Name, "status", contract.Status,
	)

	analysisResult, err := o.analyzer.Analyze(ctx, chainID, address)
	if err != nil {
		result.Analyses = []*AnalyzeResult{analysisResult}
		result.Duration = time.Since(start)
		result.Summary = fmt.Sprintf("Analysis failed for %s on chain %d: %v", address, chainID, err)
		return result, err
	}
	result.Analyses = []*AnalyzeResult{analysisResult}
	result.Reports = o.reportActionableFindings(ctx, analysisResult)

	result.Duration = time.Since(start)
	result.Summary = o.buildSingleContractSummary(chainID, address, analysisResult, result.Reports)

	o.logger.Info("single contract processing complete",
		"chain_id", chainID, "address", address,
		"duration", result.Duration,
		"findings", analysisResult.TotalFindings,
		"reports", len(result.Reports),
	)

	return result, nil
}

// ReAnalyzeContract forces a re-analysis of a previously analyzed contract.
func (o *Orchestrator) ReAnalyzeContract(ctx context.Context, chainID uint64, address string) (*AnalyzeResult, error) {
	o.logger.Info("re-analyzing contract", "chain_id", chainID, "address", address)
	return o.analyzer.ReAnalyze(ctx, chainID, address)
}

// GenerateReport generates a report for a specific finding by ID.
func (o *Orchestrator) GenerateReport(ctx context.Context, findingID string) (*ReportResult, error) {
	o.logger.Info("generating report for finding", "finding_id", findingID)
	return o.reporter.GenerateForFinding(ctx, findingID)
}

// DisplayReport retrieves and returns the full Markdown content of a previously
// generated report for the given finding ID. It looks up the report path in the
// store and reads the file from disk.
func (o *Orchestrator) DisplayReport(ctx context.Context, findingID string) (string, error) {
	o.logger.Info("displaying report for finding", "finding_id", findingID)
	return o.reporter.GetReportContent(ctx, findingID)
}

// ListContracts returns tracked contracts matching the given filter, letting
// the agent see discovered contracts and their statuses (pending, analyzed, failed, etc.).
func (o *Orchestrator) ListContracts(ctx context.Context, filter store.ContractFilter) ([]store.Contract, error) {
	o.logger.Info("listing contracts", "status", filter.Status, "chain_id", filter.ChainID)
	contracts, err := o.discovery.ListContracts(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing contracts: %w", err)
	}
	o.logger.Info("contracts listed", "count", len(contracts))
	return contracts, nil
}

// GeneratePoC generates only the proof-of-concept code for a finding.
func (o *Orchestrator) GeneratePoC(ctx context.Context, findingID string) (string, error) {
	o.logger.Info("generating PoC for finding", "finding_id", findingID)
	return o.reporter.GeneratePoCOnly(ctx, findingID)
}

// OrchestratorSystemPrompt returns the system instruction for the root ADK agent.
func OrchestratorSystemPrompt() string {
	return `You are BiM, an AI-powered smart contract exploit hunter.

Your SOLE MISSION is to discover newly published smart contracts on Ethereum and Base
and find EXTREMELY CRITICAL vulnerabilities where a third-party attacker (not the owner,
not an admin) can steal or permanently lock user or protocol funds. You then generate
bug bounty reports with proof-of-concept exploit code demonstrating the fund theft.

You do NOT care about:
- Gas optimizations, code quality, or best practices
- Centralization risks, admin abuse, or rugpull vectors
- Denial of service, front-running, or MEV without direct fund theft
- Medium, Low, or Informational severity findings
- High severity findings that do not involve direct loss of funds via third-party exploitation
- Theoretical concerns without a concrete, step-by-step exploit path

You ONLY report findings where an unprivileged external attacker can profitably steal funds.
A report with zero findings is a good report. False positives waste everyone's time.

## Background Polling

BiM runs a background discovery loop that continuously polls for new verified contracts
at the configured poll interval (default: 60s). New contracts are automatically ingested
into the store with status "pending" — ready for analysis. You do NOT need to call
discover_contracts manually for routine discovery; the background loop handles it.

Use **discovery_status** to check what the background loop has found so far.

## Core Pipeline Tools

1. **discover_contracts** — Trigger an immediate on-demand discovery cycle (in addition to background polling).
   Chains that were already polled within the current interval are skipped automatically.

2. **list_contracts** — List tracked contracts and their statuses. Supports filtering by status
   (pending, analyzing, analyzed, reported, skipped, failed) and chain ID.

3. **analyze_contract** — Run security analysis on a verified contract looking for critical
   fund-theft vulnerabilities exploitable by third-party attackers.

4. **generate_report** — Generate a bug bounty report with PoC exploit code for a Critical finding.
   Only generates reports for findings where an attacker can steal funds.

5. **display_report** — Display the full Markdown content of a previously generated report.

6. **run_pipeline** — Run the full discover → analyze → report pipeline automatically.

7. **generate_poc** — Generate only the Foundry proof-of-concept exploit code for a finding.

8. **reanalyze_contract** — Force a re-analysis of a previously analyzed contract.

9. **discovery_status** — Check the background discovery loop status.

## Usage Patterns

When the user asks you to:
- "Find new contracts" or "What's new?" → Use discovery_status first, then discover_contracts.
- "Is the background loop running?" or "What has been found?" → Use discovery_status.
- "Show me all contracts" or "What's pending?" → Use list_contracts (with status filter if appropriate).
- "Which contracts failed?" → Use list_contracts with status "failed".
- "Analyze 0x..." → Use analyze_contract.
- "Generate a report for..." → Use generate_report.
- "Show me the report" or "Display the report for..." → Use display_report.
- "Run a full scan" → Use run_pipeline.
- "Re-analyze 0x..." → Use reanalyze_contract.

## Research Strategy

For broad surveillance:
1. Use discovery_status to see what the background loop has already found.
2. Use list_contracts to see all tracked contracts and identify pending or failed ones.
3. Use discover_contracts to trigger an immediate cycle if needed.
4. Use analyze_contract on pending contracts, or run_pipeline for automated end-to-end processing.

Always present results clearly:
- Only highlight Critical findings where a third-party attacker can steal funds.
- If no critical fund-theft vulnerabilities were found, say so clearly — that is a good outcome.
- When reports are generated, mention what funds are at risk and the attack vector.
- Do NOT pad results with non-critical findings to appear productive.

Be concise. Focus exclusively on exploitable fund-theft vulnerabilities by external attackers.`
}

func (o *Orchestrator) buildPipelineSummary(result *PipelineResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## BiM Pipeline Run Complete\n\n")
	fmt.Fprintf(&b, "**Duration:** %s\n\n", result.Duration.Round(time.Millisecond))

	if result.Discovery != nil {
		fmt.Fprintf(&b, "### Discovery\n\n")
		fmt.Fprintf(&b, "- **New contracts found:** %d\n", result.Discovery.TotalNew)
		fmt.Fprintf(&b, "- **Total checked:** %d\n", result.Discovery.TotalChecked)
		fmt.Fprintf(&b, "- **Already seen:** %d\n\n", result.Discovery.TotalAlreadySeen)

		for _, cr := range result.Discovery.ChainResults {
			if len(cr.NewContracts) > 0 {
				fmt.Fprintf(&b, "**%s:** %d new contracts\n", cr.ChainName, len(cr.NewContracts))
				for _, addr := range cr.NewContracts {
					fmt.Fprintf(&b, "  - `%s`\n", addr)
				}
				b.WriteString("\n")
			}
		}
	}

	if len(result.Analyses) > 0 {
		fmt.Fprintf(&b, "### Analysis\n\n")
		fmt.Fprintf(&b, "- **Contracts analyzed:** %d\n", len(result.Analyses))

		var totalFindings, totalCritical int
		for _, ar := range result.Analyses {
			totalFindings += ar.TotalFindings
			totalCritical += ar.CriticalCount
		}

		fmt.Fprintf(&b, "- **Total findings:** %d\n", totalFindings)
		fmt.Fprintf(&b, "- **Critical (fund-theft):** %d\n\n", totalCritical)

		for _, ar := range result.Analyses {
			switch {
			case ar.Error != "":
				fmt.Fprintf(&b, "- `%s` (chain %d): **FAILED** — %s\n", ar.Address, ar.ChainID, ar.Error)
			case ar.CriticalCount > 0:
				fmt.Fprintf(&b, "- `%s` (chain %d): **%d Critical fund-theft vulnerabilities found**\n",
					ar.Address, ar.ChainID, ar.CriticalCount)
			default:
				fmt.Fprintf(&b, "- `%s` (chain %d): no critical fund-theft vulnerabilities\n",
					ar.Address, ar.ChainID)
			}
		}
		b.WriteString("\n")
	}

	if len(result.Reports) > 0 {
		fmt.Fprintf(&b, "### Reports\n\n")
		fmt.Fprintf(&b, "- **Reports generated:** %d\n\n", len(result.Reports))

		for _, rr := range result.Reports {
			if rr.Error != "" {
				fmt.Fprintf(&b, "- [%s] %s: **FAILED** — %s\n", rr.Severity, rr.Title, rr.Error)
			} else {
				fmt.Fprintf(&b, "- [%s] %s\n", rr.Severity, rr.Title)
				fmt.Fprintf(&b, "  - Report: `%s`\n", rr.ReportPath)
			}
		}
		b.WriteString("\n")
	}

	if result.Discovery != nil && result.Discovery.TotalNew == 0 && len(result.Analyses) == 0 {
		fmt.Fprintf(&b, "No new contracts discovered and no pending analyses. Everything is up to date.\n")
	}

	return b.String()
}

func (o *Orchestrator) buildSingleContractSummary(
	chainID uint64,
	address string,
	analysis *AnalyzeResult,
	reports []*ReportResult,
) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Analysis of `%s` on %s (chain %d)\n\n", address, o.cfg.ChainName(chainID), chainID)

	if analysis.Error != "" {
		fmt.Fprintf(&b, "**Analysis failed:** %s\n", analysis.Error)
		return b.String()
	}

	if analysis.ContractName != "" {
		fmt.Fprintf(&b, "**Contract:** %s\n", analysis.ContractName)
	}
	fmt.Fprintf(&b, "**Language:** %s\n\n", analysis.Language)

	fmt.Fprintf(&b, "### Findings Summary\n\n")
	fmt.Fprintf(&b, "| Category | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| Critical (fund-theft by third party) | %d |\n", analysis.CriticalCount)
	fmt.Fprintf(&b, "| Other (not reported) | %d |\n\n", analysis.TotalFindings-analysis.CriticalCount)

	criticalFindings := false
	for _, f := range analysis.Findings {
		if f.Severity == analyzer.SeverityCritical {
			if !criticalFindings {
				fmt.Fprintf(&b, "### Critical Fund-Theft Vulnerabilities\n\n")
				criticalFindings = true
			}
			fmt.Fprintf(&b, "- **%s**\n", f.Title)
			fmt.Fprintf(&b, "  - Function: `%s`\n", f.AffectedFunction)
			fmt.Fprintf(&b, "  - Confidence: %.0f%%\n", f.Confidence*100)
			if f.Impact != "" {
				fmt.Fprintf(&b, "  - Impact: %s\n", f.Impact)
			}
			b.WriteString("\n")
		}
	}

	if len(reports) > 0 {
		fmt.Fprintf(&b, "### Generated Reports\n\n")
		for _, rr := range reports {
			if rr.Error != "" {
				fmt.Fprintf(&b, "- [%s] %s: **FAILED** — %s\n", rr.Severity, rr.Title, rr.Error)
			} else {
				fmt.Fprintf(&b, "- [%s] %s\n", rr.Severity, rr.Title)
				fmt.Fprintf(&b, "  - Report: `%s`\n", rr.ReportPath)
			}
		}
	} else if analysis.CriticalCount == 0 {
		fmt.Fprintf(&b, "No critical fund-theft vulnerabilities found — no bug bounty reports generated.\n")
	}

	return b.String()
}

// reportActionableFindings generates reports for all Critical fund-theft findings
// in the given analysis result, returning results as they complete.
func (o *Orchestrator) reportActionableFindings(ctx context.Context, ar *AnalyzeResult) []*ReportResult {
	var reports []*ReportResult
	for _, f := range ar.Findings {
		if !f.Severity.IsActionable() {
			continue
		}
		if ctx.Err() != nil {
			break
		}

		rr, err := o.reporter.GenerateForFinding(ctx, f.ID)
		if err != nil {
			o.logger.Error("report generation failed",
				"finding_id", f.ID, "error", err,
			)
			reports = append(reports, &ReportResult{
				FindingID: f.ID,
				ChainID:   ar.ChainID,
				Address:   ar.Address,
				Error:     err.Error(),
			})
			continue
		}
		reports = append(reports, rr)
	}
	return reports
}

func countNewContracts(dr *DiscoverResult) int {
	if dr == nil {
		return 0
	}
	return dr.TotalNew
}
