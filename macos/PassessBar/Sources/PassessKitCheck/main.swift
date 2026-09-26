import Foundation
import PassessKit

// Headless checks for PassessKit. The fixtures are written by the Go tests
// (go test ./internal/cli -run TestMenuBarFixtures -update), so a change to the
// CLI's JSON that the app cannot read fails here.

var failures = 0
func expect(_ ok: Bool, _ message: String) {
    if !ok {
        failures += 1
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
    }
}

let dir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "Fixtures"
// AgentJSON.decoder reads Go's times, nine fractional digits and all.
func load<T: Decodable>(_ type: T.Type, _ name: String) -> T {
    let url = URL(fileURLWithPath: dir).appendingPathComponent(name)
    do {
        return try AgentJSON.decoder.decode(type, from: Data(contentsOf: url))
    } catch {
        FileHandle.standardError.write(Data("FAIL: \(name): \(error)\n".utf8))
        exit(1)
    }
}

// doctor
let healthy = load(Doctor.self, "doctor-ok.json")
expect(health(healthy) == .ok, "healthy doctor should be .ok")
let fine = headline(doctor: healthy, failure: nil)
expect(fine.title == "All clear" && fine.detail == "1 secret · 0 profiles", "healthy headline: \(fine)")
expect(problems(healthy).isEmpty, "no problems when healthy")

let broken = load(Doctor.self, "doctor-problems.json")
expect(health(broken) == .error, "doctor with an error problem should be .error")
expect(headline(doctor: broken, failure: nil).title == "1 problem", "problem headline")
let issue = problems(broken).first
expect(issue?.tone == .error && issue?.symbol == "xmark.octagon.fill", "an error problem looks like one")
if case .copy = issue?.action {} else { expect(false, "a problem with a fix can be copied") }
expect(backends(broken).first?.tone == .warning && backends(broken).first?.title == "vault", "an unusable backend is flagged")

let missing = load(Doctor.self, "doctor-no-config.json")
expect(health(missing) == .error, "missing config should be .error")
expect(headline(doctor: missing, failure: nil).title == "No config yet", "missing config headline")

expect(headline(doctor: nil, failure: nil).title == "Checking…", "no report yet is shown as checking")
expect(headline(doctor: nil, failure: "boom").detail == "boom", "a failure is shown when there is no report")
expect(health(nil) == .unknown, "no report is .unknown")
expect(reportLines(doctor: healthy, failure: nil).first == "health: ok", "the printed report starts with health")

// check
let check = load(Check.self, "check.json")
let items = checkItems(check)
expect(items.count == check.secrets.count, "one item per secret")
expect(items.contains { $0.title == "PRESENT" && $0.detail?.hasPrefix("env://") == true && $0.tone == .ok }, "resolved secret shows its source")
expect(items.contains { $0.title == "ABSENT" && $0.tone == .error }, "missing secret is flagged")
expect(checkSummary(check).text == "1 of 2 resolve" && checkSummary(check).tone == .warning, "check summary")

// agent
let running = load(AgentStatus.self, "agent-status.json")
expect(running.running && running.pid == 4242, "a running agent decodes with its pid")
let card = agentCard(running, approving: true)
expect(card?.running == true && card?.status.hasPrefix("Holds 1 value until") == true, "running agent status: \(String(describing: card?.status))")
expect(card?.holds == ["GITHUB_TOKEN"], "cached names are shown")
expect(card?.approvals.first?.title == "GITHUB_TOKEN → gh", "a live Allow is shown")
expect(card?.approvals.first?.detail?.hasPrefix("claude · until") == true, "an Allow names its caller")

let stopped = load(AgentStatus.self, "agent-status-stopped.json")
expect(!stopped.running && stopped.pid == nil, "a stopped agent decodes as not running")
expect(agentCard(stopped, approving: false)?.status.hasPrefix("Off") == true, "stopped agent status")
expect(agentCard(nil, approving: false) == nil, "an agent the CLI cannot report has no card")

let frame = load(AgentFrame.self, "agent-ask.json")
if let ask = frame.ask {
    let ask = askCard(ask, home: "/Users/you")
    expect(ask.title == "claude wants GITHUB_TOKEN" && ask.program == "for gh", "question title: \(ask.title)")
    expect(ask.command == "gh api user" && ask.directory == "~/project", "question command and directory")
    expect(ask.caller == "claude, pid 4242 · reports claude-code", "question caller: \(ask.caller)")
    expect(ask.footnote.contains("The value never reaches this app."), "question footnote")
} else {
    expect(false, "agent-ask.json holds a question")
}

// coding agents
let status = load(HarnessStatus.self, "status.json")
let agents = codingAgents(status)
expect(agents.map(\.id) == ["codex", "claude", "claude-desktop"], "agents that need setup come first: \(agents.map(\.id))")
expect(agents[0].tone == .warning && agents[0].fix == "passess install codex --apply", "an agent missing hooks offers the install command")
expect(agents[0].detail == "no hooks · instructions · 1 MCP server", "agent detail: \(agents[0].detail)")
expect(agents[1].tone == .ok && agents[1].monogram == "CC" && agents[1].fix == nil, "a guarded agent")
expect(agents[2].tone == .neutral && agents[2].detail == "Nothing set up", "an agent with nothing to set up")

expect(AgentJSON.socketPath(environment: [:], home: "/h") == "/h/.local/state/passess/agent.sock", "default socket path")
expect(AgentJSON.socketPath(environment: ["PASSESS_AGENT_SOCK": "/s"], home: "/h") == "/s", "PASSESS_AGENT_SOCK wins")
expect(AgentJSON.socketPath(environment: ["XDG_RUNTIME_DIR": "/run/u"], home: "/h") == "/run/u/passess/agent.sock",
       "XDG_RUNTIME_DIR is honored")

if failures > 0 {
    FileHandle.standardError.write(Data("\(failures) check(s) failed\n".utf8))
    exit(1)
}
print("PassessKit: all checks passed")
