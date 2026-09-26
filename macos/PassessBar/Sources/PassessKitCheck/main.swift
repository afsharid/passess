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
func load<T: Decodable>(_ type: T.Type, _ name: String) -> T {
    let url = URL(fileURLWithPath: dir).appendingPathComponent(name)
    do {
        return try JSONDecoder().decode(type, from: Data(contentsOf: url))
    } catch {
        FileHandle.standardError.write(Data("FAIL: \(name): \(error)\n".utf8))
        exit(1)
    }
}

let healthy = load(Doctor.self, "doctor-ok.json")
expect(health(healthy) == .ok, "healthy doctor should be .ok")
let healthyRows = rows(doctor: healthy, failure: nil)
expect(healthyRows.first?.isHeader == true, "first row is the version header")
expect(healthyRows.contains { $0.title.hasPrefix("Config: 1 secret, 0 profiles") }, "config summary row")
expect(healthyRows.contains { $0.title == "Everything looks fine" }, "all-clear row")

let broken = load(Doctor.self, "doctor-problems.json")
expect(health(broken) == .error, "doctor with an error problem should be .error")
let brokenRows = rows(doctor: broken, failure: nil)
expect(brokenRows.contains { row in
    if case .copy = row.action { return true }
    return false
}, "a problem with a fix becomes a copy action")
expect(brokenRows.contains { $0.title.contains("not usable") }, "an unusable backend is shown")

let missing = load(Doctor.self, "doctor-no-config.json")
expect(health(missing) == .error, "missing config should be .error")
expect(!missing.config.ok, "missing config decodes as not ok")

let check = load(Check.self, "check.json")
let checkRows = rows(check: check)
expect(checkRows.count == check.secrets.count, "one row per secret")
expect(checkRows.contains { $0.title.hasPrefix("PRESENT — env://") }, "resolved secret shows its source")
expect(checkRows.contains { $0.title == "ABSENT — missing" }, "missing secret shows its state")

expect(rows(doctor: nil, failure: "boom").first?.title == "boom", "a failure is shown when there is no report")
expect(health(nil) == .unknown, "no report is .unknown")

if failures > 0 {
    FileHandle.standardError.write(Data("\(failures) check(s) failed\n".utf8))
    exit(1)
}
print("PassessKit: all checks passed")
