package analyzer

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

var (
	systemTmpl   *template.Template
	analysisTmpl *template.Template
	summaryTmpl  *template.Template
	deepDiveTmpl *template.Template
)

func init() {
	var err error

	systemTmpl, err = template.New("system.tmpl").ParseFS(templatesFS, "templates/system.tmpl")
	if err != nil {
		panic(fmt.Sprintf("parsing system.tmpl: %v", err))
	}

	analysisTmpl, err = template.New("analysis.tmpl").ParseFS(templatesFS, "templates/analysis.tmpl")
	if err != nil {
		panic(fmt.Sprintf("parsing analysis.tmpl: %v", err))
	}

	summaryTmpl, err = template.New("summary.tmpl").ParseFS(templatesFS, "templates/summary.tmpl")
	if err != nil {
		panic(fmt.Sprintf("parsing summary.tmpl: %v", err))
	}

	deepDiveTmpl, err = template.New("deep-dive.tmpl").ParseFS(templatesFS, "templates/deep-dive.tmpl")
	if err != nil {
		panic(fmt.Sprintf("parsing deep-dive.tmpl: %v", err))
	}
}

// SystemPrompt returns the system-level instruction for the security analysis agent.
func SystemPrompt() string {
	var buf bytes.Buffer
	if err := systemTmpl.Execute(&buf, nil); err != nil {
		panic(fmt.Sprintf("executing system.tmpl: %v", err))
	}
	return buf.String()
}

// BuildAnalysisPrompt constructs the full analysis prompt for a contract.
func BuildAnalysisPrompt(contractName, chainName, address string, sources map[string]string, external []ExternalContract) string {
	var buf bytes.Buffer
	if err := analysisTmpl.Execute(&buf, map[string]any{
		"ChainName":     chainName,
		"Address":       address,
		"ContractName":  contractName,
		"SourceBlock":   formatSources(sources),
		"ExternalBlock": formatExternalContracts(external),
	}); err != nil {
		panic(fmt.Sprintf("executing analysis.tmpl: %v", err))
	}
	return buf.String()
}

// BuildSummaryPrompt constructs a summary prompt for a single source file.
func BuildSummaryPrompt(contractName, filePath, sourceCode string) string {
	var buf bytes.Buffer
	if err := summaryTmpl.Execute(&buf, map[string]string{
		"ContractName": contractName,
		"FilePath":     filePath,
		"SourceCode":   sourceCode,
	}); err != nil {
		panic(fmt.Sprintf("executing summary.tmpl: %v", err))
	}
	return buf.String()
}

// BuildDeepDivePrompt constructs a deep-dive prompt for flagged functions.
func BuildDeepDivePrompt(contractName string, sources map[string]string, external []ExternalContract, flaggedFunctionsJSON string) string {
	var buf bytes.Buffer
	if err := deepDiveTmpl.Execute(&buf, map[string]any{
		"ContractName":         contractName,
		"SourceBlock":          formatSources(sources),
		"ExternalBlock":        formatExternalContracts(external),
		"FlaggedFunctionsJSON": flaggedFunctionsJSON,
	}); err != nil {
		panic(fmt.Sprintf("executing deep-dive.tmpl: %v", err))
	}
	return buf.String()
}

// formatExternalContracts renders the external contract sources into a labelled
// block for injection into prompts. Returns an empty string when there are none.
func formatExternalContracts(external []ExternalContract) string {
	if len(external) == 0 {
		return ""
	}
	var b strings.Builder
	for _, ec := range external {
		label := ec.Address
		if ec.Name != "" {
			label = fmt.Sprintf("%s (%s)", ec.Name, ec.Address)
		}
		fmt.Fprintf(&b, "// === External contract: %s — role: %s ===\n", label, ec.Role)
		for path, content := range ec.Sources {
			fmt.Fprintf(&b, "// --- File: %s ---\n", path)
			b.WriteString(content)
			b.WriteString("\n\n")
		}
	}
	return b.String()
}

func formatSources(sources map[string]string) string {
	if len(sources) == 0 {
		return "<no source files>"
	}
	var b strings.Builder
	for path, content := range sources {
		fmt.Fprintf(&b, "// === File: %s ===\n", path)
		b.WriteString(content)
		b.WriteString("\n\n")
	}
	return b.String()
}

// EstimateTokenCount provides a rough token count estimate (~4 chars per token).
func EstimateTokenCount(sources map[string]string) int {
	total := 0
	for _, content := range sources {
		total += len(content)
	}
	return total / 4
}
