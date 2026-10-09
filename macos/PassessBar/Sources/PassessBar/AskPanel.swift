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
            HStack(alignment: .top, spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(Tone.warning.color.opacity(0.15))
                    Image(systemName: "key.fill")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(Tone.warning.color)
                }
                .frame(width: 40, height: 40)
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(card.title)
                        .font(.system(size: 15, weight: .semibold))
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
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.05)))
            Text(card.footnote)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Spacer()
                Button(t("Deny"), action: onDeny)
                    .keyboardShortcut(.cancelAction)
                    .controlSize(.large)
                Button(action: onAllow) {
                    Label(allowTitle, systemImage: allowTitle.contains("Touch ID") ? "touchid" : "lock.open")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
        }
        .padding(20)
        .frame(width: 400)
    }
}

struct DetailLine: View {
    let symbol: String
    let text: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .frame(width: 14)
                .accessibilityHidden(true)
            Text(text)
                .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12))
                .lineLimit(3)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
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
