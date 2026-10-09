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
L10n.override = .english // the checks below read English; Turkish has its own at the end
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

// secrets screen
let list = load(SecretList.self, "list.json")
let known = list.agents ?? []
expect(known.first == SecretList.Agent(id: "claude-code", label: "Claude Code") && known.count == 8, "agents a secret can be connected to")
let rows = secretRows(list, check: nil)
expect(rows.map(\.id) == ["GITHUB_TOKEN", "HASS_TOKEN", "OPENROUTER_API_KEY", "SUDO_PASSWORD"], "one row per secret: \(rows.map(\.id))")
expect(rows[0].agents == "Every agent" && !rows[0].asks && rows[0].tone == .neutral, "no clients list: every agent")
expect(rows[1].agents == "Claude Code" && rows[1].asks, "a secret that asks first")
expect(rows[2].agents == "Claude Code, OpenCode" && rows[2].usedBy == "Used by profile web", "agents in order, and who hands it on: \(rows[2])")
expect(rows[3].agents == "No agent", "an empty clients list: no agent")
let checked = secretRows(list, check: load(Check.self, "check.json"))
expect(checked.allSatisfy { $0.tone == .neutral }, "a check of other secrets marks none of these")
expect(clientsArgument(["opencode", "claude-code"], agents: known) == "claude-code,opencode", "ticked agents in their order")
expect(clientsArgument(Set(known.map(\.id)), agents: known) == "all", "every agent ticked is all")
expect(clientsArgument([], agents: known) == "none", "no agent ticked is none")
expect(pickedAgents(nil, agents: known).count == known.count && pickedAgents([], agents: known).isEmpty, "what opens ticked")
expect(nameProblem("2FA", taken: []) != nil && nameProblem("HASS_TOKEN", taken: list.secrets.map(\.name)) != nil
       && nameProblem("NEW_ONE", taken: list.secrets.map(\.name)) == nil, "names a secret can take")
expect(sourceText("bws://92fe9fe6-c441-4b27-b261-b4b9007117b9/HASS_TOKEN") == "bws · HASS_TOKEN"
       && sourceText("keychain://passess/github") == "keychain", "where a secret comes from, short")

let discovery = load(Discovery.self, "discover.json")
expect(discovery.backends.first?.ok == true, "discover reports its backend")
expect(discovery.secrets.contains { $0.key == "nvidia-nim" && $0.name == "NVIDIA_NIM" }, "a vault key gets a passess name")
let start = Date(timeIntervalSince1970: 1_800_000_000)
let firstLook = noteFirstSeen([:], discovery: discovery, now: start)
expect(foundRows(discovery, firstSeen: firstLook, now: start).allSatisfy { !$0.isNew }, "the first look marks nothing new")
let grown = try! AgentJSON.decoder.decode(Discovery.self, from: Data("""
{"backends": [{"scheme": "bws", "ok": true}],
 "secrets": [{"key": "GITHUB_TOKEN", "project": "ai-stack", "name": "GITHUB_TOKEN", "ref": "bws://p/GITHUB_TOKEN", "name_taken": false}]}
""".utf8))
let later = noteFirstSeen(firstLook, discovery: grown, now: start.addingTimeInterval(60))
let fresh = foundRows(grown, firstSeen: later, now: start.addingTimeInterval(120))
expect(fresh.count == 1 && fresh[0].isNew && fresh[0].detail == "bws · ai-stack", "what turns up later is new")
expect(later.count == 1, "what the vault no longer lists is forgotten")
expect(!foundRows(grown, firstSeen: later, now: start.addingTimeInterval(2 * 86_400))[0].isNew, "new for a day")

// Turkish
L10n.override = .turkish
expect(headline(doctor: healthy, failure: nil).title == "Her şey yolunda", "Turkish headline")
expect(headline(doctor: healthy, failure: nil).detail == "1 sır · 0 profil", "Turkish summary")
expect(checkSummary(check).text == "1/2 çalışıyor", "Turkish check summary")
expect(secretRows(list, check: nil)[0].agents == "Tüm ajanlar", "Turkish: every agent")
expect(usedBy(list.secrets[2]) == "Kullanan: web profili", "Turkish: used by")
L10n.override = .english

// Every string the app shows in English has Turkish. The sources sit next to
// the fixtures; a t(...) whose text is not a literal is checked where it is
// written, as a literal elsewhere.
let sources = URL(fileURLWithPath: dir).deletingLastPathComponent().appendingPathComponent("Sources")
let literal = try! NSRegularExpression(pattern: #"\bt\((?:[^()"]*\?\s*)?"((?:[^"\\]|\\.)*)"(?:\s*:\s*"((?:[^"\\]|\\.)*)")?"#)
var untranslated: Set<String> = []
for target in ["PassessBar", "PassessKit"] {
    let folder = sources.appendingPathComponent(target)
    for file in (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [] where file.hasSuffix(".swift") {
        guard file != "L10n.swift", let text = try? String(contentsOf: folder.appendingPathComponent(file), encoding: .utf8) else { continue }
        for m in literal.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            for group in 1...2 {
                guard let r = Range(m.range(at: group), in: text) else { continue }
                let english = String(text[r]).replacingOccurrences(of: #"\""#, with: "\"")
                if !english.isEmpty && !hasTurkish(english) { untranslated.insert(english) }
            }
        }
    }
}
expect(untranslated.isEmpty, "no Turkish for: \(untranslated.sorted())")

expect(AgentJSON.socketPath(environment: [:], home: "/h") == "/h/.local/state/passess/agent.sock", "default socket path")
expect(AgentJSON.socketPath(environment: ["PASSESS_AGENT_SOCK": "/s"], home: "/h") == "/s", "PASSESS_AGENT_SOCK wins")
expect(AgentJSON.socketPath(environment: ["XDG_RUNTIME_DIR": "/run/u"], home: "/h") == "/run/u/passess/agent.sock",
       "XDG_RUNTIME_DIR is honored")

if failures > 0 {
    FileHandle.standardError.write(Data("\(failures) check(s) failed\n".utf8))
    exit(1)
}
print("PassessKit: all checks passed")
