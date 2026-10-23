import AppKit
import PassessKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: exposed secrets

/// Where a credential sits in clear on this Mac, and a button that moves it. `passess scan` finds them; a .env
/// file moves to the keychain with `passess migrate env`, a transcript is
/// cleaned with `passess scan --scrub`. Every move shows passess's dry run
/// first and takes Touch ID.
final class ExposedModel: ObservableObject {
    @Published var folder: String
    @Published var transcripts = false
    @Published private(set) var report: ScanReport?
    @Published private(set) var scanning = false
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    @Published private(set) var done: String?
    @Published var dropping = false // a file is being dragged over the drop zone

    var onChange: (() -> Void)?
    private let cli = Passess.locate()
    private let valueCLI = Passess.bundled() // a move hands values to passess: only the copy inside the app
    private let work = DispatchQueue(label: "passess.exposed")
    private let frozen: Bool

    init() {
        let projects = NSHomeDirectory() + "/Projects"
        folder = FileManager.default.fileExists(atPath: projects) ? projects : NSHomeDirectory()
        frozen = false
    }

    /// Fixed state for previews: nothing runs.
    init(previewing report: ScanReport, folder: String) {
        self.folder = folder
        self.report = report
        frozen = true
    }

    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.directoryURL = URL(fileURLWithPath: folder)
        panel.prompt = t("Choose")
        if panel.runModal() == .OK, let url = panel.url {
            folder = url.path
            scan()
        }
    }

    func scan() {
        guard !frozen, !scanning, let cli = cli else { return }
        scanning = true
        error = nil
        let folder = self.folder, transcripts = self.transcripts
        work.async {
            var report: ScanReport?
            var failure: String?
            do { report = try cli.scan(dir: folder, transcripts: transcripts) } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.scanning = false
                self.report = report ?? self.report
                self.error = failure
            }
        }
    }

    /// Moves a .env file's values to the keychain: passess's dry run first,
    /// then Touch ID, then the move.
    func move(_ file: String) {
        guard !frozen, !busy, let cli = valueCLI else {
            if valueCLI == nil { error = t("This copy of the app has no passess inside it, so it cannot move values.") }
            return
        }
        busy = true
        error = nil
        done = nil
        work.async {
            var plan = ""
            var failure: String?
            do { plan = try cli.migrateEnv(file, apply: false) } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.busy = false
                if let failure = failure {
                    self.error = failure
                    return
                }
                let alert = NSAlert()
                alert.messageText = t("Move the values in %@ to your keychain?", (file as NSString).lastPathComponent)
                alert.informativeText = plan.trimmingCharacters(in: .whitespacesAndNewlines)
                alert.addButton(withTitle: t("Move them"))
                alert.addButton(withTitle: t("Cancel"))
                guard alert.runModal() == .alertFirstButtonReturn else { return }
                Authenticator.confirm(t("move secrets out of a file into your keychain")) { ok in
                    guard ok else { return }
                    self.run(t("Moved. The file now names the secrets; passess keeps the values.")) {
                        _ = try cli.migrateEnv(file, apply: true)
                    }
                }
            }
        }
    }

    func scrub() {
        guard !frozen, let cli = valueCLI else { return }
        let alert = NSAlert()
        alert.messageText = t("Clean the transcripts?")
        alert.informativeText = t("passess replaces the values it manages in the coding agents' session logs. The originals are backed up first.")
        alert.addButton(withTitle: t("Clean them"))
        alert.addButton(withTitle: t("Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Authenticator.confirm(t("rewrite the coding agents' transcripts")) { ok in
            guard ok else { return }
            self.run(t("Cleaned. A backup of the originals is kept.")) { try cli.scrubTranscripts() }
        }
    }

    /// Takes the .env files dropped on the window, one move each.
    func drop(_ providers: [NSItemProvider]) -> Bool {
        for p in providers {
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                guard let url = url, url.isFileURL else { return }
                DispatchQueue.main.async { self.move(url.path) }
            }
        }
        return !providers.isEmpty
    }

    private func run(_ message: String, _ change: @escaping () throws -> Void) {
        busy = true
        work.async {
            var failure: String?
            do { try change() } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.busy = false
                self.error = failure
                if failure == nil {
                    self.done = message
                    self.onChange?()
                    self.scan()
                }
            }
        }
    }
}

struct ExposedView: View {
    @ObservedObject var model: ExposedModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Badge(symbol: "exclamationmark.shield.fill", size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(t("Secrets in clear")).font(.system(size: 17, weight: .bold))
                    Text(t("Credentials in files any program of yours can read, and so any agent."))
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            HStack {
                Text(t("Project folder:")).font(.system(size: 12))
                Text(model.folder.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                    .font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Button(t("Change…"), action: model.chooseFolder).buttonStyle(.borderless)
                Spacer()
                Toggle(t("Transcripts too"), isOn: $model.transcripts).toggleStyle(.checkbox).font(.system(size: 12))
                Button(model.scanning ? t("Scanning…") : t("Scan"), action: model.scan)
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .disabled(model.scanning)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    if let report = model.report {
                        if report.findings.isEmpty {
                            Label(t("Nothing in clear in %ld files.", report.files), systemImage: "checkmark.seal.fill")
                                .font(.system(size: 13)).foregroundStyle(Tone.ok.color)
                        }
                        ForEach(report.byFile, id: \.path) { group in
                            FileGroup(path: group.path, category: group.category, findings: group.findings, model: model)
                        }
                        if report.transcriptsHoldValues {
                            HStack {
                                Text(t("Transcripts hold values passess manages.")).font(.system(size: 12))
                                Spacer()
                                Button(t("Clean them…"), action: model.scrub).buttonStyle(PrimaryButtonStyle(compact: true))
                            }
                            .padding(10).surface()
                        }
                        ForEach(report.notes ?? [], id: \.self) { Text($0).font(.system(size: 11)).foregroundStyle(.secondary) }
                    } else {
                        Text(t("Scan to see what is exposed. The scan reads files; nothing changes until you move something."))
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 300)

            HStack {
                Image(systemName: "tray.and.arrow.down")
                Text(t("Drop a .env file here to move its values to your keychain."))
            }
            .font(.system(size: 12))
            .foregroundStyle(model.dropping ? Brand.text : .secondary)
            .frame(maxWidth: .infinity)
            .padding(12)
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [5]))
                .foregroundStyle(model.dropping ? Brand.text : Color.secondary.opacity(0.5)))
            .onDrop(of: [.fileURL], isTargeted: $model.dropping, perform: model.drop)

            if let error = model.error {
                Text(error).font(.system(size: 11)).foregroundStyle(Tone.error.color).fixedSize(horizontal: false, vertical: true)
            } else if let done = model.done {
                Label(done, systemImage: "checkmark.circle.fill").font(.system(size: 11)).foregroundStyle(Tone.ok.color)
            }
        }
        .padding(20)
        .frame(width: 560)
        .disabled(model.busy)
    }
}

private struct FileGroup: View {
    let path: String
    let category: String
    let findings: [ScanReport.Finding]
    @ObservedObject var model: ExposedModel

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                    .font(.system(size: 12, weight: .semibold, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Spacer()
                Button(t("Show")) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                    .buttonStyle(.borderless)
                if category == "env" {
                    Button(t("Move to keychain…")) { model.move(path) }.buttonStyle(PrimaryButtonStyle(compact: true))
                }
            }
            ForEach(findings) { f in
                Text(t("line %ld · %@", f.line, f.kind == "known" ? t("the value of %@", f.what) : f.what))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if category == "config" {
                Text(t("A coding agent's config: move its MCP server's credentials with Settings → MCP servers."))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .surface()
    }
}

// MARK: activity

/// What the agent ran and what was approved, newest first: `passess
/// activity`. Names and programs only.
final class ActivityModel: ObservableObject {
    @Published private(set) var entries: [ActivityEntry] = []
    @Published var filter = ""
    @Published var refusedOnly = false
    @Published private(set) var error: String?
    // The log is a file next to the agent's socket; reading it needs no agent of
    // the same build, so the app's own copy, which knows `activity`, reads it.
    private let cli = Passess.locate()

    init() { load() }

    init(previewing entries: [ActivityEntry]) { self.entries = entries }

    func load() {
        guard let cli = cli else { return }
        DispatchQueue.global().async {
            var got: [ActivityEntry] = []
            var failure: String?
            do { got = try cli.activity() } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.entries = got
                self.error = failure
            }
        }
    }

    var shown: [ActivityEntry] {
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        return entries.filter { e in
            (!refusedOnly || e.refused)
                && (f.isEmpty || e.secrets.contains { $0.lowercased().contains(f) } || (e.program ?? "").lowercased().contains(f)
                    || (e.anchor ?? "").lowercased().contains(f))
        }
    }
}

struct ActivityView: View {
    @ObservedObject var model: ActivityModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                TextField(t("Filter by secret, program or caller"), text: $model.filter).textFieldStyle(.roundedBorder)
                Toggle(t("Refusals only"), isOn: $model.refusedOnly).toggleStyle(.checkbox).font(.system(size: 12))
                Button(action: model.load) { Image(systemName: "arrow.clockwise") }.buttonStyle(.borderless).help(t("Reload"))
            }
            if model.shown.isEmpty {
                Text(model.entries.isEmpty ? t("No activity yet: the agent records what it runs and what you approve.") : t("Nothing matches."))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(model.shown) { e in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            ToneIcon(symbol: e.refused ? "xmark.octagon.fill" : "checkmark.circle.fill", tone: e.refused ? .error : .ok)
                            VStack(alignment: .leading, spacing: 1) {
                                Text("\(e.secrets.joined(separator: ", ")) → \(e.program ?? "?")").font(.system(size: 12, design: .monospaced))
                                Text([outcomeText(e), e.anchor, e.dir?.replacingOccurrences(of: NSHomeDirectory(), with: "~")]
                                    .compactMap { $0 }.joined(separator: " · "))
                                    .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            Text(e.time.formatted(date: .abbreviated, time: .shortened)).font(.system(size: 11).monospacedDigit())
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 360)
            if let error = model.error {
                Text(error).font(.system(size: 11)).foregroundStyle(Tone.error.color)
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private func outcomeText(_ e: ActivityEntry) -> String {
        switch e.outcome {
        case "ran": return t("ran")
        case "refused": return t("refused")
        case "failed": return t("failed")
        case "allowed": return t("allowed")
        case "denied": return t("denied")
        case "timeout": return t("no answer in time")
        case "no-approver": return t("no one to ask")
        case "cancelled": return t("cancelled")
        case "revoked": return t("taken back")
        default: return e.outcome
        }
    }
}

/// A plain window for either view, one at a time each.
final class ToolWindow: NSWindow, NSWindowDelegate {
    private var onClose: (() -> Void)?

    init<V: View>(title: String, view: V, onClose: @escaping () -> Void) {
        super.init(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.onClose = onClose
        self.title = title
        isReleasedWhenClosed = false
        delegate = self
        let controller = NSHostingController(rootView: view)
        controller.sizingOptions = .preferredContentSize
        contentViewController = controller
        setContentSize(controller.view.fittingSize)
        center()
    }

    func windowWillClose(_ notification: Notification) {
        let close = onClose
        onClose = nil
        close?()
    }
}
