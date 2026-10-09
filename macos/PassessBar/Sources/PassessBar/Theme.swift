import AppKit
import PassessKit
import SwiftUI

// Three color systems, each with one job: the brand (the app icon's green)
// for actions and the app's own marks; the tones (green, orange, red) for
// status, always beside a symbol; an agent color for each coding agent's
// avatar, and nowhere else.

enum Brand {
    /// Buttons, switches, ticks: the icon's middle green, a shade lighter in
    /// dark mode so it still stands off the window.
    static let tint = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? rgb(0x2E8A73) : rgb(0x1E6B5A)
    })
    /// Text and outlines in the brand color: lighter in dark mode, to read.
    static let text = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? rgb(0x63C7AA) : rgb(0x1E6B5A)
    })
    /// The icon's gradient, top to bottom.
    static let gradient = LinearGradient(colors: [Color(nsColor: rgb(0x3FA58B)), Color(nsColor: rgb(0x1E6B5A)),
                                                  Color(nsColor: rgb(0x14453B))],
                                         startPoint: .top, endPoint: .bottom)
}

func rgb(_ hex: UInt32) -> NSColor {
    NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}

extension Tone {
    /// A badge's fill: the brand for fine, the tone's color otherwise.
    var gradient: LinearGradient {
        switch self {
        case .ok: return Brand.gradient
        case .warning: return LinearGradient(colors: [Color(nsColor: rgb(0xF5A524)), Color(nsColor: rgb(0xC26A0A))],
                                             startPoint: .top, endPoint: .bottom)
        case .error: return LinearGradient(colors: [Color(nsColor: rgb(0xF2555A)), Color(nsColor: rgb(0xB42318))],
                                           startPoint: .top, endPoint: .bottom)
        case .neutral: return LinearGradient(colors: [Color(nsColor: rgb(0x9AA1AB)), Color(nsColor: rgb(0x5F6672))],
                                             startPoint: .top, endPoint: .bottom)
        }
    }
}

/// How a coding agent looks: its app's own icon when that app is installed,
/// otherwise a color and two letters. Both ID spaces are known: passess status
/// says "claude", a clients list says "claude-code".
struct AgentStyle {
    let color: NSColor
    let monogram: String

    static func of(_ id: String, label: String) -> AgentStyle {
        switch id {
        case "claude", "claude-code": return AgentStyle(color: rgb(0xC15F3C), monogram: "CC")
        case "claude-desktop": return AgentStyle(color: rgb(0x9A4A2E), monogram: "CD")
        case "codex": return AgentStyle(color: rgb(0x3F3F46), monogram: "Cx")
        case "opencode": return AgentStyle(color: rgb(0x2563EB), monogram: "OC")
        case "kiro": return AgentStyle(color: rgb(0x7C3AED), monogram: "K")
        case "antigravity": return AgentStyle(color: rgb(0xA16207), monogram: "AG")
        case "cursor": return AgentStyle(color: rgb(0xBE185D), monogram: "Cu")
        case "gemini", "gemini-cli": return AgentStyle(color: rgb(0x4F46E5), monogram: "G")
        case "zed": return AgentStyle(color: rgb(0x0E7490), monogram: "Z")
        case "dsh": return AgentStyle(color: rgb(0x4D6BFE), monogram: "DS")
        case "vscode": return AgentStyle(color: rgb(0x0B5CAD), monogram: "VS")
        case "windsurf": return AgentStyle(color: rgb(0x0F766E), monogram: "W")
        default: return AgentStyle(color: rgb(0x5F6672), monogram: String(label.prefix(2)))
        }
    }

    /// The apps whose icons stand for each agent, by bundle ID; the first one
    /// installed wins. A CLI agent borrows its maker's app. The icon is read
    /// from the app on this Mac, so passess ships no one's logo.
    static let apps: [String: [String]] = [
        "claude": ["com.anthropic.claudefordesktop"], "claude-code": ["com.anthropic.claudefordesktop"],
        "claude-desktop": ["com.anthropic.claudefordesktop"], "codex": ["com.openai.codex"],
        "opencode": ["ai.opencode.desktop"], "kiro": ["dev.kiro.desktop", "com.amazon.codewhisperer"],
        "antigravity": ["com.google.antigravity", "com.google.antigravity-ide"],
        "cursor": ["com.todesktop.230313mzl4w4u92"], "gemini": ["com.google.GeminiMacOS"],
        "gemini-cli": ["com.google.GeminiMacOS"], "zed": ["dev.zed.Zed"], "dsh": ["com.deepseek.dsh"],
        "vscode": ["com.microsoft.VSCode"], "windsurf": ["com.exafunction.windsurf"],
    ]

    /// Icons looked up so far, nil for an agent with no app installed: the
    /// panel redraws often, and Launch Services is not free.
    @MainActor private static var icons: [String: NSImage?] = [:]

    /// The icon of the agent's app, or nil when none of its apps is installed.
    @MainActor static func icon(_ id: String) -> NSImage? {
        if let known = icons[id] { return known }
        let url = (apps[id] ?? []).lazy.compactMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }.first
        let image = url.map { NSWorkspace.shared.icon(forFile: $0.path) }
        icons[id] = image
        return image
    }
}

/// A coding agent's mark: its app's icon, or its two letters on its color.
struct AgentAvatar: View {
    let id: String
    let label: String
    var size: CGFloat = 26

    var body: some View {
        if let icon = AgentStyle.icon(id) {
            Image(nsImage: icon)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
                .accessibilityLabel(label)
        } else {
            monogram
        }
    }

    private var monogram: some View {
        let style = AgentStyle.of(id, label: label)
        let base = Color(nsColor: style.color)
        return Text(style.monogram)
            .font(.system(size: size * 0.4, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(
                RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                    .fill(LinearGradient(colors: [base.opacity(0.82), base], startPoint: .top, endPoint: .bottom))
            )
            .overlay(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).strokeBorder(.white.opacity(0.18), lineWidth: 0.5))
            .accessibilityLabel(label)
    }
}

/// The agents a secret is connected to, as overlapping avatars.
struct AvatarStack: View {
    let ids: [String]
    let agents: [SecretList.Agent]
    var size: CGFloat = 18
    var limit = 4

    var body: some View {
        HStack(spacing: -size * 0.3) {
            ForEach(Array(ids.prefix(limit)), id: \.self) { id in
                AgentAvatar(id: id, label: agents.first { $0.id == id }?.label ?? id, size: size)
                    .overlay(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                        .strokeBorder(Color(nsColor: .controlBackgroundColor), lineWidth: 1.5))
            }
            if ids.count > limit {
                Text("+\(ids.count - limit)")
                    .font(.system(size: size * 0.45, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                    .padding(.leading, size * 0.45)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A short label on a soft capsule of its color.
struct Pill: View {
    let text: String
    var symbol: String?
    var tint: Color = Brand.text

    var body: some View {
        HStack(spacing: 3) {
            if let symbol = symbol {
                Image(systemName: symbol).font(.system(size: 9, weight: .bold))
            }
            Text(text).font(.system(size: 10.5, weight: .semibold))
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .foregroundStyle(tint)
        .background(Capsule().fill(tint.opacity(0.14)))
        .fixedSize()
    }
}

/// A white symbol on a gradient tile, like the app icon.
struct Badge: View {
    let symbol: String
    var gradient: LinearGradient = Brand.gradient
    var size: CGFloat = 38

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.46, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.27, style: .continuous).fill(gradient))
            .overlay(RoundedRectangle(cornerRadius: size * 0.27, style: .continuous).strokeBorder(.white.opacity(0.2), lineWidth: 0.5))
            .shadow(color: .black.opacity(0.15), radius: 2, y: 1)
            .accessibilityHidden(true)
    }
}

/// The one action a view is for (Connect, Save): white on the brand, drawn by
/// SwiftUI so it looks the same in every window. The gradient stays in the
/// icon's darker half, where white text reads.
struct PrimaryButtonStyle: ButtonStyle {
    var compact = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: compact ? 12 : 13, weight: .semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, compact ? 10 : 15)
            .padding(.vertical, compact ? 4 : 7)
            .background(
                RoundedRectangle(cornerRadius: compact ? 7 : 8, style: .continuous)
                    .fill(LinearGradient(colors: [Color(nsColor: rgb(0x2E8A73)), Color(nsColor: rgb(0x1A5E4F))],
                                         startPoint: .top, endPoint: .bottom))
            )
            .overlay(RoundedRectangle(cornerRadius: compact ? 7 : 8, style: .continuous).strokeBorder(.white.opacity(0.18), lineWidth: 0.5))
            .shadow(color: .black.opacity(configuration.isPressed ? 0 : 0.18), radius: 1.5, y: 1)
            .opacity(enabled ? (configuration.isPressed ? 0.82 : 1) : 0.45)
            .contentShape(Rectangle())
    }
}

/// A switch in the brand's color when on, drawn by SwiftUI like the primary
/// button: the system's own turns grey in a window that is not key. It shows
/// no label; the row around it says what it does, and the caller names it
/// for VoiceOver.
struct BrandSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                Capsule()
                    .fill(configuration.isOn ? AnyShapeStyle(Brand.tint) : AnyShapeStyle(Color.primary.opacity(0.18)))
                    .frame(width: 34, height: 20)
                Circle()
                    .fill(.white)
                    .shadow(color: .black.opacity(0.25), radius: 1, y: 0.5)
                    .frame(width: 16, height: 16)
                    .padding(2)
            }
            .animation(.easeOut(duration: 0.15), value: configuration.isOn)
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? t("On") : t("Off"))
    }
}

/// The ground cards sit on: a raised surface with a hairline edge. Not a
/// material: the previews render offscreen, where materials come out wrong.
struct Surface: ViewModifier {
    var highlighted = false

    func body(content: Content) -> some View {
        content
            .background(
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor))
                        .shadow(color: .black.opacity(0.06), radius: 3, y: 1)
                    if highlighted {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(Brand.tint.opacity(0.08))
                    }
                }
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(highlighted ? Brand.text.opacity(0.55) : Color.primary.opacity(0.08), lineWidth: highlighted ? 1 : 0.5)
            )
    }
}

extension View {
    func surface(highlighted: Bool = false) -> some View {
        modifier(Surface(highlighted: highlighted))
    }
}
