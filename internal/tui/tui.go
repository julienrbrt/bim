package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// progRef is a shared holder for the *tea.Program reference so that
// every copy of Model (and the LogSink) can reach the same program.
type progRef struct {
	mu sync.Mutex
	p  *tea.Program
}

func newProgRef() *progRef { return &progRef{} }

func (r *progRef) Set(p *tea.Program) {
	r.mu.Lock()
	r.p = p
	r.mu.Unlock()
}

func (r *progRef) Ready() bool {
	r.mu.Lock()
	ok := r.p != nil
	r.mu.Unlock()
	return ok
}

func (r *progRef) Send(msg tea.Msg) {
	r.mu.Lock()
	p := r.p
	r.mu.Unlock()
	if p != nil {
		p.Send(msg)
	}
}

// TUI message types.
type agentChunkMsg struct{ text string }
type agentDoneMsg struct{ err error }
type agentToolCallMsg struct{ tool string }
type agentToolResultMsg struct{ tool string }
type agentStatusMsg struct{ text string }

// PipelineProgressMsg is sent by the orchestrator's progress callback to
// display live pipeline status in the chat tab.
type PipelineProgressMsg struct {
	Phase   string
	Message string
}
type clearCtrlCMsg struct{}

const (
	tabChat = iota
	tabLogs
)

// Pretty tool-name mapping.
var toolDisplayNames = map[string]string{
	"discover_contracts": "Discovering contracts",
	"list_contracts":     "Listing contracts",
	"analyze_contract":   "Analyzing contract",
	"generate_report":    "Generating report",
	"display_report":     "Displaying report",
	"run_pipeline":       "Running full pipeline",
	"generate_poc":       "Generating PoC exploit",
	"reanalyze_contract": "Re-analyzing contract",
	"discovery_status":   "Checking discovery status",
}

func prettyToolName(name string) string {
	if pretty, ok := toolDisplayNames[name]; ok {
		return pretty
	}
	return name
}

// Config holds the TUI dependencies.
type Config struct {
	Runner    *runner.Runner
	SessionID string
	UserID    string
	Ctx       context.Context
}

// Model is the top-level Bubbletea model for BiM.
type Model struct {
	cfg Config

	activeTab int

	chatVP viewport.Model
	logsVP viewport.Model
	input  textinput.Model

	chatLines []string
	logLines  []string

	agentBusy    bool
	agentPartial string
	agentStatus  string
	agentCancel  context.CancelFunc // cancels the running agent request

	ctrlCPending bool // true after first Ctrl+C when agent is busy

	chatAtBottom bool // true when the chat viewport is pinned to the bottom
	logsAtBottom bool // true when the logs viewport is pinned to the bottom

	width  int
	height int

	pref    *progRef
	logSink *LogSink

	ready bool
}

// New creates the initial Model.
func New(cfg Config) Model {
	ti := textinput.New()
	ti.Prompt = "> "
	ti.Placeholder = "Ask BiM something…"
	ti.Focus()
	ti.CharLimit = 4096

	return Model{
		cfg:          cfg,
		activeTab:    tabChat,
		chatVP:       viewport.New(),
		logsVP:       viewport.New(),
		input:        ti,
		chatLines:    []string{"Welcome to BiM. Type a message and press Enter."},
		logLines:     []string{},
		pref:         newProgRef(),
		chatAtBottom: true,
		logsAtBottom: true,
	}
}

// ProgRef returns the shared program reference.
func (m *Model) ProgRef() *progRef {
	return m.pref
}

// SetProgram stores the program in the shared ref.
func (m *Model) SetProgram(p *tea.Program) {
	m.pref.Set(p)
}

// SetRunnerConfig fills in Runner, SessionID and UserID after construction.
func (m *Model) SetRunnerConfig(r *runner.Runner, sessionID, userID string) {
	m.cfg.Runner = r
	m.cfg.SessionID = sessionID
	m.cfg.UserID = userID
}

// SetLogSink stores the LogSink for flushing queued lines on Init.
func (m *Model) SetLogSink(s *LogSink) {
	m.logSink = s
}

// tea.Model interface.

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.input.Focus()}
	if m.logSink != nil {
		if flushCmd := m.logSink.FlushQueued(); flushCmd != nil {
			cmds = append(cmds, flushCmd)
		}
	}
	return tea.Batch(cmds...)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m.recalcLayout()
		return m, nil

	case clearCtrlCMsg:
		m.ctrlCPending = false
		return m, nil

	case tea.KeyPressMsg:
		switch {
		// Ctrl+C: cancel agent on first press, quit on second (or when idle).
		case msg.Code == 'c' && msg.Mod == tea.ModCtrl:
			if m.agentBusy && !m.ctrlCPending {
				// First Ctrl+C while agent is running — cancel the request.
				if m.agentCancel != nil {
					m.agentCancel()
				}
				m.ctrlCPending = true
				m.chatLines = append(m.chatLines, dimStyle().Render("  ✖ Cancelling request… (press Ctrl+C again to quit)"))
				m.syncChatViewport()
				// Reset the pending flag after 2 seconds so a late
				// second press doesn't accidentally quit.
				return m, tea.Tick(2*time.Second, func(time.Time) tea.Msg {
					return clearCtrlCMsg{}
				})
			}
			// Second Ctrl+C (or first when agent is idle) — quit.
			return m, tea.Quit

		// Switch tabs
		case msg.Code == tea.KeyTab && msg.Mod == 0:
			m.activeTab = (m.activeTab + 1) % 2
			return m, nil

		// Submit prompt
		case msg.Code == tea.KeyEnter && msg.Mod == 0 && m.activeTab == tabChat:
			if m.agentBusy {
				return m, nil
			}
			text := strings.TrimSpace(m.input.Value())
			if text == "" {
				return m, nil
			}
			m.input.SetValue("")
			m.chatLines = append(m.chatLines, "You: "+text)
			m.agentBusy = true
			m.agentPartial = ""
			m.agentStatus = "Starting…"
			m.ctrlCPending = false
			m.chatAtBottom = true
			m.syncChatViewport()
			return m, m.runAgent(text)
		}

		// Chat tab: textinput handles typing; otherwise forward to viewport.
		if m.activeTab == tabChat {
			switch msg.Code {
			case tea.KeyUp, tea.KeyPgUp:
				m.chatAtBottom = false
				vp, cmd := m.chatVP.Update(msg)
				m.chatVP = vp
				cmds = append(cmds, cmd)
			case tea.KeyDown, tea.KeyPgDown:
				vp, cmd := m.chatVP.Update(msg)
				m.chatVP = vp
				cmds = append(cmds, cmd)
				m.chatAtBottom = m.chatVP.AtBottom()
			default:
				ti, cmd := m.input.Update(msg)
				m.input = ti
				cmds = append(cmds, cmd)
			}
		} else {
			switch msg.Code {
			case tea.KeyUp, tea.KeyPgUp:
				m.logsAtBottom = false
				vp, cmd := m.logsVP.Update(msg)
				m.logsVP = vp
				cmds = append(cmds, cmd)
			case tea.KeyDown, tea.KeyPgDown:
				vp, cmd := m.logsVP.Update(msg)
				m.logsVP = vp
				cmds = append(cmds, cmd)
				m.logsAtBottom = m.logsVP.AtBottom()
			default:
				vp, cmd := m.logsVP.Update(msg)
				m.logsVP = vp
				cmds = append(cmds, cmd)
			}
		}

		return m, tea.Batch(cmds...)

	case logLineMsg:
		m.logLines = append(m.logLines, msg.line)
		m.syncLogsViewport()
		return m, nil

	case agentChunkMsg:
		m.agentPartial += msg.text
		m.agentStatus = "Streaming response…"
		m.syncChatViewport()
		return m, nil

	case agentToolCallMsg:
		m.agentStatus = prettyToolName(msg.tool) + "…"
		m.chatLines = append(m.chatLines, fmt.Sprintf("  ⚙ Calling %s", prettyToolName(msg.tool)))
		m.syncChatViewport()
		return m, nil

	case agentToolResultMsg:
		m.agentStatus = prettyToolName(msg.tool) + " done, processing…"
		m.chatLines = append(m.chatLines, fmt.Sprintf("  ✔ %s complete", prettyToolName(msg.tool)))
		m.syncChatViewport()
		return m, nil

	case PipelineProgressMsg:
		m.agentStatus = msg.Message
		m.chatLines = append(m.chatLines, "  📊 "+msg.Message)
		m.syncChatViewport()
		return m, nil

	case agentStatusMsg:
		m.agentStatus = msg.text
		m.syncChatViewport()
		return m, nil

	case agentDoneMsg:
		m.agentBusy = false
		m.agentStatus = ""
		m.agentCancel = nil
		m.ctrlCPending = false
		if msg.err != nil {
			if msg.err == context.Canceled {
				m.chatLines = append(m.chatLines, dimStyle().Render("  ✖ Request cancelled."))
			} else {
				m.chatLines = append(m.chatLines, "Error: "+msg.err.Error())
			}
		} else if m.agentPartial != "" {
			m.chatLines = append(m.chatLines, "BiM: "+m.agentPartial)
		}
		m.agentPartial = ""
		m.syncChatViewport()
		return m, nil
	}

	// Forward remaining messages (mouse, etc.) to sub-components.
	if m.activeTab == tabChat {
		vp, cmd := m.chatVP.Update(msg)
		m.chatVP = vp
		cmds = append(cmds, cmd)
		// If the viewport moved (e.g. mouse wheel scroll), update the pin state.
		if !m.chatVP.AtBottom() {
			m.chatAtBottom = false
		} else {
			m.chatAtBottom = true
		}
		ti, cmd2 := m.input.Update(msg)
		m.input = ti
		cmds = append(cmds, cmd2)
	} else {
		vp, cmd := m.logsVP.Update(msg)
		m.logsVP = vp
		cmds = append(cmds, cmd)
		// If the viewport moved (e.g. mouse wheel scroll), update the pin state.
		if !m.logsVP.AtBottom() {
			m.logsAtBottom = false
		} else {
			m.logsAtBottom = true
		}
	}

	return m, tea.Batch(cmds...)
}

func (m Model) View() tea.View {
	if !m.ready {
		v := tea.NewView("Initialising…")
		v.AltScreen = true
		return v
	}

	tabBar := m.renderTabBar()

	var body string
	if m.activeTab == tabChat {
		body = m.chatVP.View()
	} else {
		body = m.logsVP.View()
	}

	var inputLine string
	if m.activeTab == tabChat {
		inputLine = m.input.View()
	} else {
		inputLine = dimStyle().Render("(switch to Chat tab to type)")
	}

	content := lipgloss.JoinVertical(lipgloss.Left, tabBar, body, inputLine)

	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

// Layout helpers.

func (m *Model) recalcLayout() {
	vpHeight := max(
		// tab bar + input
		m.height-2, 1)

	m.chatVP.SetWidth(m.width)
	m.chatVP.SetHeight(vpHeight)
	m.logsVP.SetWidth(m.width)
	m.logsVP.SetHeight(vpHeight)
	m.input.SetWidth(m.width)

	m.syncChatViewport()
	m.syncLogsViewport()
}

func (m *Model) syncChatViewport() {
	lines := make([]string, len(m.chatLines))
	copy(lines, m.chatLines)

	if m.agentPartial != "" {
		lines = append(lines, "BiM: "+m.agentPartial+"▍")
	} else if m.agentBusy && m.agentStatus != "" {
		lines = append(lines, "  ⏳ "+m.agentStatus)
	}

	styled := make([]string, len(lines))
	for i, l := range lines {
		styled[i] = styleChatLine(l)
	}

	content := strings.Join(styled, "\n")
	if m.width > 0 {
		content = lipgloss.Wrap(content, m.width, "")
	}
	m.chatVP.SetContent(content)
	if m.chatAtBottom {
		m.chatVP.GotoBottom()
	}
}

func (m *Model) syncLogsViewport() {
	styled := make([]string, len(m.logLines))
	for i, l := range m.logLines {
		styled[i] = styleLogLine(l)
	}
	content := strings.Join(styled, "\n")
	if m.width > 0 {
		content = lipgloss.Wrap(content, m.width, "")
	}
	m.logsVP.SetContent(content)
	if m.logsAtBottom {
		m.logsVP.GotoBottom()
	}
}

// ADK runner.

func (m *Model) runAgent(input string) tea.Cmd {
	r := m.cfg.Runner
	parentCtx := m.cfg.Ctx
	userID := m.cfg.UserID
	sid := m.cfg.SessionID
	ref := m.pref

	ctx, cancel := context.WithCancel(parentCtx)
	m.agentCancel = cancel

	return func() tea.Msg {
		defer cancel()

		userMsg := genai.NewContentFromText(input, genai.RoleUser)

		ref.Send(agentStatusMsg{text: "Sending to model…"})

		for event, err := range r.Run(ctx, userID, sid, userMsg, agent.RunConfig{}) {
			if err != nil {
				return agentDoneMsg{err: err}
			}
			if event == nil || event.Content == nil {
				continue
			}

			for _, p := range event.Content.Parts {
				if p.FunctionCall != nil {
					ref.Send(agentToolCallMsg{tool: p.FunctionCall.Name})
					continue
				}
				if p.FunctionResponse != nil {
					ref.Send(agentToolResultMsg{tool: p.FunctionResponse.Name})
					continue
				}
				if p.Text != "" {
					ref.Send(agentChunkMsg{text: p.Text})
				}
			}
		}

		return agentDoneMsg{}
	}
}

// Tab bar.

func (m Model) renderTabBar() string {
	chatLabel := " Chat "
	logsLabel := " Logs "

	if m.activeTab == tabChat {
		chatLabel = activeTabStyle().Render(chatLabel)
		logsLabel = inactiveTabStyle().Render(logsLabel)
	} else {
		chatLabel = inactiveTabStyle().Render(chatLabel)
		logsLabel = activeTabStyle().Render(logsLabel)
	}

	sep := dimStyle().Render("│")
	bar := chatLabel + sep + logsLabel

	if m.agentBusy && m.agentStatus != "" {
		bar += dimStyle().Render("  ⏳ " + m.agentStatus)
	}

	return lipgloss.NewStyle().Width(m.width).Render(bar)
}

// Styles.

func activeTabStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Bold(true).
		Underline(true).
		Foreground(lipgloss.ANSIColor(6)) // cyan
}

func inactiveTabStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Faint(true)
}

func dimStyle() lipgloss.Style {
	return lipgloss.NewStyle().Faint(true)
}

func toolCallStyle() lipgloss.Style {
	return lipgloss.NewStyle().Faint(true).Foreground(lipgloss.ANSIColor(5)) // magenta
}

func toolResultStyle() lipgloss.Style {
	return lipgloss.NewStyle().Faint(true).Foreground(lipgloss.ANSIColor(2)) // green
}

func statusStyle() lipgloss.Style {
	return lipgloss.NewStyle().Faint(true).Foreground(lipgloss.ANSIColor(3)) // yellow
}

func pipelineProgressStyle() lipgloss.Style {
	return lipgloss.NewStyle().Faint(true).Foreground(lipgloss.ANSIColor(4)) // blue
}

func pipelineAlertStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.ANSIColor(1)) // bold red
}

func pipelineSuccessStyle() lipgloss.Style {
	return lipgloss.NewStyle().Faint(true).Foreground(lipgloss.ANSIColor(2)) // green
}

func pipelineErrorStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(1)) // red
}

func styleChatLine(line string) string {
	switch {
	case strings.HasPrefix(line, "You: "):
		prefix := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.ANSIColor(6)).Render("You:")
		return prefix + " " + line[5:]
	case strings.HasPrefix(line, "BiM: "):
		prefix := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.ANSIColor(2)).Render("BiM:")
		return prefix + " " + line[5:]
	case strings.HasPrefix(line, "Error: "):
		return lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(1)).Render(line)
	case strings.HasPrefix(line, "  ⚙ "):
		return toolCallStyle().Render(line)
	case strings.HasPrefix(line, "  ✔ "):
		return toolResultStyle().Render(line)
	case strings.HasPrefix(line, "  ⏳ "):
		return statusStyle().Render(line)
	case strings.HasPrefix(line, "  📊 "):
		content := line[len("  📊 "):]
		switch {
		case strings.Contains(content, "🚨"):
			return pipelineAlertStyle().Render(line)
		case strings.Contains(content, "❌"), strings.Contains(content, "⚠️"), strings.Contains(content, "FAILED"):
			return pipelineErrorStyle().Render(line)
		case strings.Contains(content, "✅"), strings.Contains(content, "🏁"):
			return pipelineSuccessStyle().Render(line)
		default:
			return pipelineProgressStyle().Render(line)
		}
	default:
		return dimStyle().Render(line)
	}
}

func styleLogLine(line string) string {
	s := dimStyle()
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "ERROR"):
		s = s.Foreground(lipgloss.ANSIColor(1)) // red
	case strings.Contains(upper, "WARN"):
		s = s.Foreground(lipgloss.ANSIColor(3)) // yellow
	}
	return s.Render(line)
}

// EnsureSession creates an in-memory session if one doesn't exist and returns its ID.
func EnsureSession(ctx context.Context, svc session.Service, appName, userID, sessionID string) (string, error) {
	_, err := svc.Get(ctx, &session.GetRequest{
		AppName:   appName,
		UserID:    userID,
		SessionID: sessionID,
	})
	if err == nil {
		return sessionID, nil
	}

	resp, err := svc.Create(ctx, &session.CreateRequest{
		AppName:   appName,
		UserID:    userID,
		SessionID: sessionID,
	})
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return resp.Session.ID(), nil
}
