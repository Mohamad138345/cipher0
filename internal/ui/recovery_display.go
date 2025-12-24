// Package ui provides the TUI interface for the password manager.
package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type RecoveryDisplayModel struct {
	phrase    string
	words     []string
	confirmed bool
}

func NewRecoveryDisplayModel(phrase string) *RecoveryDisplayModel {
	return &RecoveryDisplayModel{phrase: phrase, words: strings.Fields(phrase)}
}

func (m *RecoveryDisplayModel) Init() tea.Cmd { return nil }

func (m *RecoveryDisplayModel) Update(msg tea.Msg) (*RecoveryDisplayModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "c", "C":
			m.confirmed = true
		case "enter":
			if m.confirmed {
				return m, NavigateTo(ScreenMain, nil)
			}
		case "esc", "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *RecoveryDisplayModel) View(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Recovery", contentWidth))
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("RECOVERY PHRASE"))
	b.WriteString("\n\n")

	// Warning
	b.WriteString(WarningStyle.Render("⚠ SAVE THESE WORDS!"))
	b.WriteString("\n\n")

	// Words grid
	if len(m.words) >= 12 {
		for i := range 6 {
			left := DimStyle.Render(fmt.Sprintf(" %2d.", i+1)) + " " + BaseStyle.Render(fmt.Sprintf("%-12s", m.words[i]))
			right := DimStyle.Render(fmt.Sprintf("%2d.", i+7)) + " " + BaseStyle.Render(fmt.Sprintf("%-12s", m.words[i+6]))
			b.WriteString(left + "    " + right + "\n")
		}
	}
	b.WriteString("\n")

	// Info
	b.WriteString(DimStyle.Render("    This is the ONLY way to recover your vault."))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("    Never share or store digitally."))
	b.WriteString("\n\n")

	// Confirmation
	if m.confirmed {
		b.WriteString(SuccessStyle.Render("✓ Confirmed - saved securely"))
	} else {
		b.WriteString(DimStyle.Render("Press 'c' to confirm"))
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Confirm", "c"},
		{"Continue", "enter"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
