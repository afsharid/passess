import AppKit
import LocalAuthentication
import PassessKit

/// Answers the agent's approval questions. While the agent runs, the app stays
/// connected to it as an approver. Each question gets a window of its own;
/// Allow needs the user's Touch ID or password (.deviceOwnerAuthentication)
/// before the answer is sent. The app never receives a value, only names and
/// the command.
final class ApproverController {
    /// Called on the main thread when connected changes.
    var onChange: (() -> Void)?
    private(set) var connected = false

    private let reader = DispatchQueue(label: "passess.bar.approver")
    private var connection: AgentConnection? // main thread
    private var queue: [AgentAsk] = [] // main thread: questions not shown yet
    private var showing: AgentAsk? // main thread
    private var panel: AskPanel? // main thread
    private var settled: Set<String> = [] // main thread: answered elsewhere

    func start() {
        reader.async { self.loop() }
    }

    // MARK: connection (reader queue)

    private func loop() {
        while true {
            do {
                let c = try AgentConnection(path: AgentJSON.socketPath())
                try c.send(AgentRequest(kind: "approver"))
                let first = try c.readFrame()
                if let refusal = first.error {
                    throw AgentConnection.Failure.refused(refusal)
                }
                DispatchQueue.main.async { self.attach(c) }
                while true {
                    let frame = try c.readFrame()
                    DispatchQueue.main.async { self.handle(frame) }
                }
            } catch {
                DispatchQueue.main.async { self.detach() }
                Thread.sleep(forTimeInterval: 3) // the agent may start later
            }
        }
    }

    // MARK: questions (main thread)

    private func attach(_ c: AgentConnection) {
        connection = c
        connected = true
        onChange?()
    }

    private func detach() {
        guard connected else { return }
        connection = nil
        connected = false
        // The agent sends every open question again to the next approver.
        queue.removeAll()
        dismiss()
        onChange?()
    }

    private func handle(_ frame: AgentFrame) {
        if let ask = frame.ask {
            queue.append(ask)
            showNext()
        } else if let id = frame.cancel {
            settled.insert(id)
            queue.removeAll { $0.id == id }
            if showing?.id == id {
                dismiss()
                showNext()
            }
        }
    }

    private func showNext() {
        guard showing == nil, !queue.isEmpty else { return }
        let ask = queue.removeFirst()
        guard !settled.contains(ask.id) else { return showNext() }
        showing = ask
        let panel = AskPanel(card: askCard(ask), allowTitle: allowTitle(),
                             onAllow: { [weak self] in self?.authenticate(ask) },
                             onDeny: { [weak self] in self?.answer(ask, allow: false) })
        panel.onClose = { [weak self] in self?.answer(ask, allow: false) }
        self.panel = panel
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    /// Touch ID, or the password. A cancelled prompt leaves the question on
    /// screen, to allow again or deny.
    private func authenticate(_ ask: AgentAsk) {
        let context = LAContext()
        let reason = "allow \(ask.secrets.joined(separator: ", ")) for \(ask.program)"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
            guard ok else { return }
            DispatchQueue.main.async { self.answer(ask, allow: true) }
        }
    }

    private func answer(_ ask: AgentAsk, allow: Bool) {
        guard showing?.id == ask.id else { return }
        if !settled.contains(ask.id) {
            try? connection?.write(AgentAnswer(id: ask.id, allow: allow))
        }
        dismiss()
        showNext()
    }

    private func dismiss() {
        panel?.dismiss()
        panel = nil
        showing = nil
    }

    private func allowTitle() -> String {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error), context.biometryType == .touchID {
            return "Allow with Touch ID"
        }
        return "Allow…"
    }
}
