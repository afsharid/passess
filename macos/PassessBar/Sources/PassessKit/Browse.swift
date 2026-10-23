import Foundation

/// Output of `passess browse op --json`: a 1Password account's vaults, a
/// vault's items, or an item's fields, by name. Mirrors opBrowseOutput in
/// internal/cli/browse.go; it never carries a value.
public struct OPBrowse: Decodable, Equatable {
    public struct Entry: Decodable, Equatable, Identifiable {
        public let id: String
        public let name: String
        public let category: String? // items
        public let section: String?  // fields
        public let type: String?     // fields: CONCEALED, STRING, …
        public let ref: String?      // fields: op://vault/item/[section/]field
        public let usedBy: String?   // fields: the passess secret with that reference

        enum CodingKeys: String, CodingKey {
            case id, name, category, section, type, ref
            case usedBy = "used_by"
        }
    }

    public let vault: String?
    public let item: String?
    public let vaults: [Entry]?
    public let items: [Entry]?
    public let fields: [Entry]?
}

/// Output of `passess browse keychain --json`: passess's own keychain items,
/// by account. Mirrors keychainBrowseOutput in internal/cli/browse.go.
public struct KeychainBrowse: Decodable, Equatable {
    public struct Entry: Decodable, Equatable, Identifiable {
        public var id: String { ref }
        public let account: String
        public let ref: String
        public let modified: String?
        public let usedBy: String?
        /// The backend whose own credential this is (bws's machine token):
        /// never offered as a secret.
        public let backend: String?

        enum CodingKeys: String, CodingKey {
            case account, ref, modified, backend
            case usedBy = "used_by"
        }
    }

    public let service: String
    public let items: [Entry]
}

/// A 1Password field as the Add tab lists it: its label, its section and
/// whether passess has it already.
public func fieldText(_ f: OPBrowse.Entry) -> (title: String, detail: String) {
    var parts: [String] = []
    if let s = f.section, !s.isEmpty { parts.append(s) }
    if let type = f.type, !type.isEmpty { parts.append(type.lowercased()) }
    if let used = f.usedBy { parts.append(t("used by %@", used)) }
    return (f.name, parts.joined(separator: " · "))
}

/// The fields worth offering first: concealed ones (passwords, tokens), then
/// the rest; notes and fields without a reference last.
public func orderedFields(_ fields: [OPBrowse.Entry]) -> [OPBrowse.Entry] {
    func rank(_ f: OPBrowse.Entry) -> Int {
        if f.ref == nil { return 3 }
        if f.type == "CONCEALED" { return 0 }
        if f.name == "notesPlain" { return 2 }
        return 1
    }
    return fields.enumerated().sorted { (rank($0.element), $0.offset) < (rank($1.element), $1.offset) }.map(\.element)
}

/// A passess name for a vault item: "GitHub" with field "read token" becomes
/// GITHUB_READ_TOKEN; a field named credential, password or the like adds
/// nothing.
public func suggestedName(item: String, field: String?) -> String {
    var words = [item]
    if let f = field, !["credential", "password", "token", "api key", "notesplain"].contains(f.lowercased()) {
        words.append(f)
    }
    let joined = words.joined(separator: "_").uppercased()
    var out = ""
    for scalar in joined.unicodeScalars {
        if ("A"..."Z").contains(Character(scalar)) || ("0"..."9").contains(Character(scalar)) {
            out.unicodeScalars.append(scalar)
        } else if !out.hasSuffix("_") {
            out += "_"
        }
    }
    out = out.trimmingCharacters(in: CharacterSet(charactersIn: "_"))
    if out.isEmpty { return "SECRET" }
    if let first = out.first, first.isNumber { out = "SECRET_" + out }
    return out
}

/// Why a typed reference cannot be added, or nil: it must name a backend
/// passess reads (scheme://…). The CLI checks the rest.
public func referenceProblem(_ text: String) -> String? {
    let r = text.trimmingCharacters(in: .whitespaces)
    let schemes = ["op", "keychain", "vault", "bw", "bws", "env"]
    guard let range = r.range(of: "://"), schemes.contains(String(r[..<range.lowerBound])), !r[range.upperBound...].isEmpty else {
        return t("Write a reference such as op://vault/item/field or vault://path#key.")
    }
    return nil
}
