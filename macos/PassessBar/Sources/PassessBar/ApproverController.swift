import AppKit
import LocalAuthentication
import PassessKit

/// Answers the agent's approval questions. While the agent runs, the app stays
/// connected to it as an approver. Each question becomes an alert whose
/// default button is Deny; Allow needs the user's Touch ID or password
/// (.deviceOwnerAuthentication) before the answer is sent. The app never
/// receives a value, only names and the command.
final class ApproverController {
    /// Called on the main thread when connected changes.
    var onChange: (() -> Void)?
    private(set) var connected = false

    private let reader = DispatchQueue(label: "passess.bar.approver")
    private var connection: AgentConnection? // main thread
    private var queue: [AgentAsk] = [] // main thread: questions not shown yet
    private var showing: AgentAsk? // main thread
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
        if showing != nil { NSApp.abortModal() }
        onChange?()
    }

    private func handle(_ frame: AgentFrame) {
        if let ask = frame.ask {
            queue.append(ask)
            showNext()
        } else if let id = frame.cancel {
            settled.insert(id)
            queue.removeAll { $0.id == id }
            if showing?.id == id { NSApp.abortModal() }
        }
    }

    private func showNext() {
        guard showing == nil, !queue.isEmpty else { return }
        let ask = queue.removeFirst()
        guard !settled.contains(ask.id) else { return showNext() }
        showing = ask
        let text = askText(ask)
        let alert = NSAlert()
        alert.messageText = text.title
        alert.informativeText = text.detail
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Deny") // Return denies
        alert.addButton(withTitle: "Allow…")
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        switch response {
        case .alertSecondButtonReturn:
            authenticate(ask)
        case .alertFirstButtonReturn:
            answer(ask, allow: false)
        default: // aborted: answered elsewhere, or the agent went away
            finish()
        }
    }

    private func authenticate(_ ask: AgentAsk) {
        let context = LAContext()
        let reason = "allow \(ask.secrets.joined(separator: ", ")) for \(ask.program)"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
            DispatchQueue.main.async { self.answer(ask, allow: ok) }
        }
    }

    private func answer(_ ask: AgentAsk, allow: Bool) {
        if !settled.contains(ask.id) {
            try? connection?.write(AgentAnswer(id: ask.id, allow: allow))
        }
        finish()
    }

    private func finish() {
        showing = nil
        showNext()
    }
}
