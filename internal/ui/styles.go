// Package ui provides the TUI interface for the password manager.
// Clean modern two-panel layout style without separator lines.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Clean minimal color palette
var (
	// Main colors
	ColorCyan     = lipgloss.Color("#00D7FF")
	ColorGreen    = lipgloss.Color("#00FF87")
	ColorYellow   = lipgloss.Color("#FFFF5F")
	ColorRed      = lipgloss.Color("#FF5F5F")
	ColorMagenta  = lipgloss.Color("#FF87FF")
	ColorWhite    = lipgloss.Color("#FFFFFF")
	ColorGray     = lipgloss.Color("#6C6C6C")
	ColorDarkGray = lipgloss.Color("#3A3A3A")

	// Aliases
	ColorPrimary = ColorCyan
	ColorAccent  = ColorGreen
	ColorText    = ColorWhite
	ColorMuted   = ColorGray
	ColorSubtle  = ColorDarkGray
	ColorSuccess = ColorGreen
	ColorWarning = ColorYellow
	ColorError   = ColorRed

	// Surface colors
	ColorOnSurface        = ColorText
	ColorOnSurfaceVariant = ColorMuted
	ColorOutline          = ColorDarkGray
	ColorSurfaceVariant   = lipgloss.Color("#1E1E1E")
	ColorOverlay          = ColorSurfaceVariant
)

// Icons
const (
	IconBox     = "□"
	IconBoxFill = "■"
)

// Typography styles
var (
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	LogoStyle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	SectionStyle = lipgloss.NewStyle().
			Foreground(ColorWhite).
			Bold(true)

	BaseStyle = lipgloss.NewStyle().
			Foreground(ColorWhite)

	LabelStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	DimStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	ValueStyle = lipgloss.NewStyle().
			Foreground(ColorWhite)
)

// Status styles
var (
	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorRed)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorGreen)

	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorYellow)
)

// Input styles
var (
	InputStyle = lipgloss.NewStyle().
			Foreground(ColorWhite)

	InputFocusedStyle = lipgloss.NewStyle().
				Foreground(ColorCyan)

	InputPlaceholderStyle = lipgloss.NewStyle().
				Foreground(ColorGray)

	PromptStyle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			SetString("> ")
)

// List item styles
var (
	TableRowStyle = lipgloss.NewStyle().
			Foreground(ColorWhite)

	TableSelectedRowStyle = lipgloss.NewStyle().
				Foreground(ColorCyan).
				Bold(true)

	TableHeaderStyle = lipgloss.NewStyle().
				Foreground(ColorGray)
)

// Bottom bar
var (
	StatusBarStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	StatusKeyStyle = lipgloss.NewStyle().
			Foreground(ColorWhite)

	StatusDescStyle = lipgloss.NewStyle().
			Foreground(ColorGray)
)

// Strength indicators
var (
	StrengthWeakStyle       = lipgloss.NewStyle().Foreground(ColorRed)
	StrengthFairStyle       = lipgloss.NewStyle().Foreground(ColorYellow)
	StrengthGoodStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))
	StrengthStrongStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#90EE90"))
	StrengthVeryStrongStyle = lipgloss.NewStyle().Foreground(ColorGreen)
)

// TOTP styles
var (
	TOTPCodeStyle = lipgloss.NewStyle().
			Foreground(ColorGreen).
			Bold(true)

	TOTPTimerStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	TOTPTimerUrgentStyle = lipgloss.NewStyle().
				Foreground(ColorYellow).
				Bold(true)
)

// Legacy aliases
var (
	CardStyle         = lipgloss.NewStyle()
	CardFocusedStyle  = lipgloss.NewStyle()
	BoxStyle          = lipgloss.NewStyle()
	FocusedBoxStyle   = lipgloss.NewStyle()
	DialogStyle       = lipgloss.NewStyle()
	PanelStyle        = lipgloss.NewStyle()
	PanelFocusedStyle = lipgloss.NewStyle()
	PanelTitleStyle   = SectionStyle

	ButtonStyle         = lipgloss.NewStyle().Foreground(ColorGray)
	ButtonFocusedStyle  = lipgloss.NewStyle().Foreground(ColorCyan)
	ButtonFilledStyle   = lipgloss.NewStyle().Foreground(ColorCyan)
	ButtonTonalStyle    = lipgloss.NewStyle().Foreground(ColorGreen)
	ButtonOutlinedStyle = lipgloss.NewStyle().Foreground(ColorGray)
	ButtonDangerStyle   = lipgloss.NewStyle().Foreground(ColorRed)

	TagStyle         = lipgloss.NewStyle().Foreground(ColorGray)
	TagSelectedStyle = lipgloss.NewStyle().Foreground(ColorCyan)

	QuoteBarStyle  = lipgloss.NewStyle().Foreground(ColorDarkGray).SetString("│")
	QuoteTextStyle = lipgloss.NewStyle().Foreground(ColorGray)
)

// Layout helpers - no separator lines

// RenderHeader renders the top header bar like: cipher0  [ Main ]
func RenderHeader(title, section string, width int) string {
	left := TitleStyle.Render("cipher0") + "  " + DimStyle.Render("[") + " " + TitleStyle.Render(section) + " " + DimStyle.Render("]")
	return left
}

// RenderSearchBar renders the search input
func RenderSearchBar(query string, focused bool, width int) string {
	content := query
	if content == "" && !focused {
		content = DimStyle.Render("Search (ctrl+f)")
	}

	cursor := ""
	if focused {
		cursor = TitleStyle.Render("█")
	}

	return content + cursor
}

// RenderSectionHeader renders a section title (no underline)
func RenderSectionHeader(title string) string {
	return SectionStyle.Render(title)
}

// RenderBottomBar renders the bottom keybindings bar (no line above)
func RenderBottomBar(items [][]string, width int) string {
	var parts []string
	for _, item := range items {
		if len(item) == 2 {
			parts = append(parts, StatusKeyStyle.Render(item[0])+" "+DimStyle.Render("("+item[1]+")"))
		}
	}
	return strings.Join(parts, DimStyle.Render("  │  "))
}

// RenderListItem renders a list item
func RenderListItem(text string, selected bool) string {
	if selected {
		return TitleStyle.Render(">") + " " + TableSelectedRowStyle.Render(text)
	}
	return "  " + BaseStyle.Render(text)
}

// RenderDetailRow renders a label: value row for details panel
func RenderDetailRow(label, value string) string {
	labelWidth := 10
	paddedLabel := fmt.Sprintf("%-*s", labelWidth, label+":")
	return LabelStyle.Render(paddedLabel) + ValueStyle.Render(value)
}

func RenderPasswordStrength(strength int) string {
	labels := []string{"weak", "fair", "good", "strong", "excellent"}
	styles := []lipgloss.Style{
		StrengthWeakStyle, StrengthFairStyle, StrengthGoodStyle,
		StrengthStrongStyle, StrengthVeryStrongStyle,
	}
	if strength < 0 {
		strength = 0
	}
	if strength >= len(labels) {
		strength = len(labels) - 1
	}
	return styles[strength].Render(labels[strength])
}

func RenderProgressBar(percent int, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := width * percent / 100
	empty := width - filled
	return StatusKeyStyle.Render(strings.Repeat("█", filled)) + DimStyle.Render(strings.Repeat("░", empty))
}

func TruncateWithEllipsis(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "…"
}

func centerContent(content string, width, height int) string {
	lines := strings.Split(content, "\n")

	maxWidth := 0
	for _, line := range lines {
		if w := lipgloss.Width(line); w > maxWidth {
			maxWidth = w
		}
	}

	leftPad := max((width-maxWidth)/2, 0)

	var centered strings.Builder
	for _, line := range lines {
		centered.WriteString(strings.Repeat(" ", leftPad) + line + "\n")
	}

	contentHeight := len(lines)
	topPad := max((height-contentHeight)/3, 1)

	return strings.Repeat("\n", topPad) + centered.String()
}

const AppLogoSmall = "🔐 PASS"
