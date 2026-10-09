import AppKit
import PassessKit
import SwiftUI

/// One approval question on screen: who wants which secret, for what, where,
/// and how long an Allow lasts. Esc denies; Return never allows.
struct AskView: View {
    let card: AskCard
    let allowTitle: String
    let onAllow: () -> Void
    let onDeny: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 14) {
                Badge(symbol: "key.fill", gradient: Tone.warning.gradient, size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text(card.title)
                        .font(.system(size: 16, weight: .bold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(card.program)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }
            VStack(alignment: .leading, spacing: 7) {
                DetailLine(symbol: "terminal", text: card.command, monospaced: true)
                DetailLine(symbol: "folder", text: card.directory)
                DetailLine(symbol: "cpu", text: card.caller)
            }
            .padding(11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .surface()
            Label {
                Text(card.footnote)
            } icon: {
                Image(systemName: "lock.shield.fill").foregroundStyle(Brand.text)
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Spacer()
                Button(t("Deny"), action: onDeny)
                    .keyboardShortcut(.cancelAction)
                    .controlSize(.large)
                Button(action: onAllow) {
                    Label(allowTitle, systemImage: allowTitle.contains("Touch ID") ? "touchid" : "lock.open")
                }
                .buttonStyle(PrimaryButtonStyle())
            }
        }
        .padding(22)
        .frame(width: 420)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Brand.tint)
    }
}

struct DetailLine: View {
    let symbol: String
    let text: String
    var monospaced = false

    var body: some View {
        HStack(alignment: text.count > DetailLine.long ? .top : .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .frame(width: 14)
                .accessibilityHidden(true)
            // Never cut: the command and the caller are the caller's own words,
            // and what a cut hides is what an Allow would let through. A long
            // one scrolls in a box of fixed height and says so.
            if text.count > DetailLine.long {
                VStack(alignment: .leading, spacing: 4) {
                    ScrollView(.vertical) {
                        line.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 120)
                    Text(t("Long: scroll to read all of it before you allow."))
                        .font(.system(size: 11))
                        .foregroundStyle(Tone.warning.color)
                }
            } else {
                line
            }
        }
    }

    /// Characters past which a line scrolls instead of growing the window.
    static let long = 240

    private var line: some View {
        Text(text)
            .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12))
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
    }
}

/// A floating window for one question. Closing it counts as Deny.
final class AskPanel: NSPanel, NSWindowDelegate {
    /// Called when the user closes the window instead of answering.
    var onClose: (() -> Void)?

    init(card: AskCard, allowTitle: String, onAllow: @escaping () -> Void, onDeny: @escaping () -> Void) {
        super.init(contentRect: .zero, styleMask: [.titled, .closable, .fullSizeContentView],
                   backing: .buffered, defer: false)
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        title = t("passess approval")
        isMovableByWindowBackground = true
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        level = .floating
        standardWindowButton(.miniaturizeButton)?.isHidden = true
        standardWindowButton(.zoomButton)?.isHidden = true
        delegate = self
        let host = NSHostingView(rootView: AskView(card: card, allowTitle: allowTitle, onAllow: onAllow, onDeny: onDeny))
        contentView = host
        setContentSize(host.fittingSize)
        center()
    }

    func windowWillClose(_ notification: Notification) {
        let close = onClose
        onClose = nil
        close?()
    }

    /// Closes the window without it counting as an answer.
    func dismiss() {
        onClose = nil
        close()
    }
}
