// Package config provides YAML-based configuration for BiM.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Chain holds metadata for a supported blockchain network.
type Chain struct {
	// ID is the unique chain identifier.
	ID uint64 `yaml:"id"`
	// Name is the human-readable name of the chain.
	Name string `yaml:"name"`
	// RPCURL is the RPC endpoint for the chain.
	RPCURL string `yaml:"rpc_url"`
}

// Config is the top-level configuration for BiM.
type Config struct {
	// GoogleAPIKey is the API key for Google Gemini.
	GoogleAPIKey string `yaml:"google_api_key"`
	// ModelName is the Gemini model identifier.
	ModelName string `yaml:"model_name"`
	// LogLevel controls the logging verbosity (debug, info, warn, error).
	LogLevel string `yaml:"log_level"`

	// DataDir is the base directory for persisted data (reports, etc.).
	DataDir string `yaml:"data_dir"`
	// DBPath is the path to the SQLite database file.
	DBPath string `yaml:"db_path"`

	// SourcifyBaseURL is the base URL for the Sourcify API.
	SourcifyBaseURL string `yaml:"sourcify_base_url"`
	// PollInterval is how often the discovery loop polls for new contracts.
	PollInterval time.Duration `yaml:"poll_interval"`
	// MaxSinglePassTokens is the token threshold above which the two-pass
	// analysis strategy is used instead of sending all sources in one request.
	MaxSinglePassTokens int `yaml:"max_single_pass_tokens"`

	// SkippedContracts is a list of contract name substrings (case-insensitive)
	// that should be skipped during analysis. Contracts whose short name or
	// fully-qualified name contains any of these substrings are marked as
	// skipped without being sent to the LLM.
	SkippedContracts []string `yaml:"skipped_contracts"`

	// Chains lists the blockchain networks BiM monitors.
	Chains []Chain `yaml:"chains"`
}

// defaults returns a Config populated with sensible defaults.
func defaults() Config {
	return Config{
		ModelName:           "gemini-2.5-pro",
		LogLevel:            "info",
		DataDir:             "./data",
		DBPath:              "./data/bim.db",
		SourcifyBaseURL:     "https://sourcify.dev/server",
		PollInterval:        60 * time.Second,
		MaxSinglePassTokens: 200_000,
		SkippedContracts: []string{
			// All OpenZeppelin contracts — matched against source file paths.
			// A single entry covers every current and future OZ contract.
			"@openzeppelin",
			// Gnosis Safe infrastructure — canonical, well-audited deployments.
			"GnosisSafe",
			"SafeProxy",
			"GnosisSafeProxy",
			"MultiSend",
			"MultiSendCallOnly",
			"SafeL2",
			"CompatibilityFallbackHandler",
			"TokenCallbackHandler",
			"CreateCall",
			"SignMessageLib",
			// Canonical singletons — never user-customised.
			"EntryPoint",
			"SenderCreator",
			"Permit2",
			// Well-known factory / utility deployments.
			"Multicall3",
			"Create2Factory",
			"DeterministicDeploymentProxy",
			// Common wrapped/canonical tokens — verbatim deployments.
			"WETH9",
			"WrappedEther",
			// Boilerplate / tutorial contracts — no real logic.
			"Counter",
			"Lock",
			"Storage",
			"SimpleStorage",
			"HelloWorld",
			"NFT",
			"Token",
			"Migrations",
			"ERC20Mock",
			"ERC721Mock",
			"ERC1155Mock",
		},
		Chains: []Chain{
			{ID: 1, Name: "Ethereum Mainnet", RPCURL: "https://eth.llamarpc.com"},
			{ID: 8453, Name: "Base", RPCURL: "https://mainnet.base.org"},
		},
	}
}

// Load reads a YAML configuration file and returns a validated Config.
// Defaults are applied first, then overridden by the file contents.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// validate checks that required fields are set and values are sane.
func (c *Config) validate() error {
	if c.GoogleAPIKey == "" {
		return fmt.Errorf("google_api_key is required")
	}
	if len(c.Chains) == 0 {
		return fmt.Errorf("at least one chain must be configured")
	}
	seen := make(map[uint64]bool, len(c.Chains))
	for i, ch := range c.Chains {
		if ch.ID == 0 {
			return fmt.Errorf("chains[%d]: id must be non-zero", i)
		}
		if ch.Name == "" {
			return fmt.Errorf("chains[%d]: name is required", i)
		}
		if ch.RPCURL == "" {
			return fmt.Errorf("chains[%d]: rpc_url is required", i)
		}
		if seen[ch.ID] {
			return fmt.Errorf("chains[%d]: duplicate chain id %d", i, ch.ID)
		}
		seen[ch.ID] = true
	}
	if c.PollInterval < time.Second {
		return fmt.Errorf("poll_interval must be at least 1s, got %s", c.PollInterval)
	}
	return nil
}

// IsContractSkipped reports whether the given contract matches any entry in the
// SkippedContracts list. Matching is case-insensitive and checked against:
//   - the fully-qualified name (e.g. "contracts/Token.sol:MyToken")
//   - the short name after the last ':' (e.g. "MyToken")
//   - each source file path (e.g. "@openzeppelin/contracts/token/ERC20/ERC20.sol")
//
// This last check allows a single entry like "@openzeppelin" to skip any
// contract whose sources live entirely under that path prefix.
func (c *Config) IsContractSkipped(fullyQualifiedName string, sourcePaths ...string) (bool, string) {
	// Extract the short name: "contracts/Token.sol:MyToken" → "MyToken".
	short := fullyQualifiedName
	if idx := strings.LastIndex(fullyQualifiedName, ":"); idx >= 0 {
		short = fullyQualifiedName[idx+1:]
	}

	nameLower := strings.ToLower(fullyQualifiedName)
	shortLower := strings.ToLower(short)

	for _, entry := range c.SkippedContracts {
		entryLower := strings.ToLower(entry)
		if strings.Contains(nameLower, entryLower) || strings.Contains(shortLower, entryLower) {
			return true, entry
		}
		for _, p := range sourcePaths {
			if strings.Contains(strings.ToLower(p), entryLower) {
				return true, entry
			}
		}
	}
	return false, ""
}

// ChainIDs returns the list of configured chain IDs.
func (c *Config) ChainIDs() []uint64 {
	ids := make([]uint64, len(c.Chains))
	for i, ch := range c.Chains {
		ids[i] = ch.ID
	}
	return ids
}

// ChainByID returns the Chain for the given ID, or an error if not configured.
func (c *Config) ChainByID(id uint64) (Chain, error) {
	for _, ch := range c.Chains {
		if ch.ID == id {
			return ch, nil
		}
	}
	return Chain{}, fmt.Errorf("unconfigured chain id: %d", id)
}

// ChainName returns the human-readable name for a chain ID.
// Returns "Chain <id>" if the chain is not configured.
func (c *Config) ChainName(id uint64) string {
	ch, err := c.ChainByID(id)
	if err != nil {
		return fmt.Sprintf("Chain %d", id)
	}
	return ch.Name
}
