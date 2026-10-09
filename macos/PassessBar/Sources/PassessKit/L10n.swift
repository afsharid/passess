import Foundation

/// The app speaks the Mac's language when it has a translation for it, and
/// English otherwise. A string is looked up by its English text, so a missing
/// translation shows English, never a key. A table in code, not .strings
/// files: the app is assembled by hand and checked headless, and both need
/// nothing but this file.
public enum L10n {
    public enum Language: Equatable {
        case english, turkish
    }

    /// nil follows the Mac's preferred languages; the headless checks pin it.
    public static var override: Language?

    public static var language: Language {
        if let pinned = override { return pinned }
        return (Locale.preferredLanguages.first ?? "en").lowercased().hasPrefix("tr") ? .turkish : .english
    }
}

/// The text in the app's language.
public func t(_ english: String) -> String {
    L10n.language == .turkish ? (turkish[english] ?? english) : english
}

/// A format in the app's language, filled in: t("%ld of %ld work", 3, 4).
/// Numbers are written plain, never grouped: a pid of 4242 stays 4242.
public func t(_ english: String, _ args: CVarArg...) -> String {
    String(format: t(english), arguments: args)
}

/// Whether the Turkish table has text for this English string, for the
/// headless check that finds untranslated ones.
public func hasTurkish(_ english: String) -> Bool {
    turkish[english] != nil
}

/// Turkish. Plain words, short sentences; "ajan" is always a coding agent,
/// "servis" the passess agent that runs in the background.
let turkish: [String: String] = [
    // header and health
    "passess cannot run": "passess çalışmıyor",
    "Checking…": "Denetleniyor…",
    "No config yet": "Henüz ayar yok",
    "passess has no config to read": "passess'in okuyacağı bir ayar yok",
    "%ld problem": "%ld sorun",
    "%ld problems": "%ld sorun",
    "%ld warning": "%ld uyarı",
    "%ld warnings": "%ld uyarı",
    "All clear": "Her şey yolunda",
    "%ld secret": "%ld sır",
    "%ld secrets": "%ld sır",
    "%ld profile": "%ld profil",
    "%ld profiles": "%ld profil",
    "Refresh": "Yenile",
    "fine": "sorun yok",
    "needs attention": "dikkat gerekiyor",
    "problem": "sorun",
    "ready": "hazır",

    // tiles
    "Agent": "Servis",
    "On": "Açık",
    "On · holds %ld": "Açık · %ld değer",
    "Off": "Kapalı",
    "%@. Click to stop: the agent forgets every value and approval.":
        "%@. Durdurmak için tıkla: servis tuttuğu her değeri ve onayı unutur.",
    "Start the agent: cached values, approvals": "Servisi başlat: değerleri kısa süre tutar, onayları sorar",
    "Update passess": "passess'i güncelle",
    "The passess on your PATH has no agent yet: brew upgrade passess":
        "PATH'teki passess'te servis yok: brew upgrade passess",
    "Secrets": "Sırlar",
    "Click to check": "Denetle",
    "Resolve every secret once and show which work. Names only; no value is shown.":
        "Her sırrı bir kez çözer ve hangilerinin çalıştığını gösterir. Yalnız adlar görünür, değer görünmez.",
    "No secrets defined yet": "Henüz sır yok",
    "%ld of %ld resolve": "%ld/%ld çalışıyor",

    // agent card
    "Off: every command asks the vault": "Kapalı: her komut kasaya yeniden sorar",
    "Cache off": "Önbellek kapalı",
    "Holds no values": "Değer tutmuyor",
    "Holds %ld value": "%ld değer tutuyor",
    "Holds %ld values": "%ld değer tutuyor",
    "Holds %ld value until %@": "%ld değer tutuyor · bitiş %@",
    "Holds %ld values until %@": "%ld değer tutuyor · bitiş %@",
    "%@ · until %@": "%@ · bitiş %@",

    // cards
    "Needs attention": "Dikkat gerektiren",
    "Coding agents": "Kodlama ajanları",
    "%ld of %ld guarded": "%ld/%ld korunuyor",
    "Approvals": "Onaylar",
    "None yet. Questions open a window of their own.": "Henüz yok. Her soru kendi penceresinde açılır.",
    "Questions go unanswered until this app connects.": "Bu uygulama bağlanana kadar sorular yanıtsız kalır.",
    "answered here": "burada yanıtlanıyor",
    "not connected": "bağlı değil",
    "Secrets that do not resolve": "Çözülemeyen sırlar",
    "Backends": "Kasalar",
    "Ready": "Hazır",
    "Not usable": "Kullanılamıyor",
    "No secret uses a vault yet": "Henüz hiçbir sır bir kasa kullanmıyor",
    "Get started": "Başlarken",
    "Add a first secret in a terminal": "İlk sırrı bir terminalde ekle",
    "Install it in a terminal": "Bir terminalde kur",
    "Copied": "Kopyalandı",
    "Copy the command that fixes it": "Düzelten komutu kopyala",
    "Copy the fix": "Düzeltmeyi kopyala",

    // coding agents
    "hooks": "hook'lar",
    "no hooks": "hook yok",
    "hooks outdated": "hook'lar eski",
    "hooks by hand": "hook'lar elle",
    "instructions": "talimatlar",
    "no instructions": "talimat yok",
    "instructions outdated": "talimatlar eski",
    "%ld MCP server": "%ld MCP sunucusu",
    "%ld MCP servers": "%ld MCP sunucusu",
    "Nothing set up": "Hiçbir şey kurulu değil",

    // footer
    "Open at Login": "Girişte aç",
    "Config": "Ayar dosyası",
    "passess on GitHub": "GitHub'da passess",
    "Help": "Yardım",
    "Quit": "Çık",
    "Could not change Open at Login": "Girişte aç ayarı değiştirilemedi",
    "Move Passess.app to /Applications and try again, or add it under System Settings → General → Login Items.":
        "Passess.app'i Uygulamalar klasörüne taşıyıp yeniden dene ya da Sistem Ayarları → Genel → Giriş Öğeleri'nden ekle.",

    // approvals
    "passess approval": "passess onayı",
    "Deny": "Reddet",
    "Allow with Touch ID": "Touch ID ile izin ver",
    "Allow…": "İzin ver…",
    "%@ wants %@": "%@, %@ sırrını istiyor",
    "for %@": "%@ için",
    "An unidentified caller": "Tanınmayan bir süreç",
    "no process passess can remember the answer for": "passess'in yanıtı hatırlayabileceği bir süreç yok",
    "%@, pid %ld": "%@, pid %ld",
    " · reports %@": " · kendini %@ olarak tanıtıyor",
    "Allowing lets %@ have it whenever this %@ asks, until %@. The value never reaches this app.":
        "İzin verirsen %1$@ bu sırrı, bu %2$@ istedikçe alır. Bitiş: %3$@. Değer bu uygulamaya hiç gelmez.",
    "Allowing counts for this one command. The value never reaches this app.":
        "İzin yalnız bu komut için geçerli. Değer bu uygulamaya hiç gelmez.",
    "allow %@ for %@": "%1$@ sırrını %2$@ programına vermek",

    // secrets screen
    "Secrets and connections": "Sırlar ve bağlantılar",
    "Show": "Göster",
    "See every secret and change who may use it": "Her sırrı gör ve kimin kullanacağını değiştir",
    "%ld not connected": "%ld bağlı değil",
    "Connected": "Bağlı",
    "Values are never shown. Every change asks for Touch ID or your password.":
        "Değerler hiçbir yerde görünmez. Her değişiklik Touch ID ya da parolanı ister.",
    "In your vault, not connected": "Kasada, henüz bağlı değil",
    "No secret matches": "Eşleşen sır yok",
    "Filter by name": "Ada göre süz",
    "Clear": "Temizle",
    "%ld agent": "%ld ajan",
    "%ld agents": "%ld ajan",
    "Works": "Çalışıyor",
    "Does not resolve": "Çözülemiyor",
    "All": "Tümü",
    "None": "Hiçbiri",
    "selected": "seçili",
    "not selected": "seçili değil",
    "New": "Yeni",
    "Connect": "Bağla",
    "%@ · %@": "%@ · %@",
    "%ld more": "%ld tane daha",
    "Every agent": "Tüm ajanlar",
    "No agent": "Hiçbir ajan",
    "Asks first": "Önce sorar",
    "Used by %@": "Kullanan: %@",
    "profile %@": "%@ profili",
    "MCP server %@": "%@ MCP sunucusu",
    "Change who may use %@": "%@ sırrını kimin kullanacağını değiştir",
    "Your vault could not be read: %@": "Kasan okunamadı: %@",

    // connect window
    "Connect %@": "%@ sırrını bağla",
    "Source: %@": "Kaynak: %@",
    "Name agents see": "Ajanların göreceği ad",
    "Use letters, digits and _; start with a letter.": "Harf, rakam ve _ kullan; harfle başla.",
    "A secret named %@ already exists.": "%@ adında bir sır zaten var.",
    "Who may use it?": "Kim kullanabilir?",
    "Ask me first": "Önce bana sor",
    "Each new program and agent waits for your OK: Touch ID or your password.":
        "Her yeni program ve ajan önce onayını bekler: Touch ID ya da parolan.",
    "The value is never shown, here or to any agent.": "Değer hiçbir yerde görünmez: ne burada ne de bir ajanda.",
    "Without an agent ticked, no agent can use it; your own terminal still can.":
        "Hiçbir ajan seçilmezse hiçbir ajan kullanamaz; kendi terminalin kullanmaya devam eder.",
    "Cancel": "Vazgeç",
    "Connect with Touch ID": "Touch ID ile bağla",
    "Save with Touch ID": "Touch ID ile kaydet",
    "Connect…": "Bağla…",
    "Save…": "Kaydet…",
    "Remove from passess": "passess'ten kaldır",
    "Remove %@ from passess?": "%@ passess'ten kaldırılsın mı?",
    "Agents can no longer use it. Your vault keeps the secret.":
        "Ajanlar artık kullanamaz. Sır kasanda kalır.",
    "Remove": "Kaldır",
    "connect %@ to coding agents": "%@ sırrını kodlama ajanlarına bağlamak",
    "change who may use %@": "%@ sırrını kimin kullanacağını değiştirmek",
    "remove %@ from passess": "%@ sırrını passess'ten kaldırmak",
    "Saving…": "Kaydediliyor…",
    "Removing it would break %@; take it out there first.": "Kaldırırsan %@ bozulur; önce orada çıkar.",
    // apps that read their own keys (ADR 11)
    "connected to every agent, not to this app by name": "tüm ajanlara bağlı; bu uygulamaya adıyla bağlı değil",
    "not connected to this app": "bu uygulamaya bağlı değil",
    "not in passess yet": "henüz passess'te yok",
    "plugin loaded": "eklenti yüklü",
    "restart it to load the plugin": "eklentiyi yüklemesi için yeniden başlat",
    "plugin ready": "eklenti hazır",
    "plugin outdated": "eklenti eski",
    "plugin not set up": "eklenti kurulmadı",
    "%ld of %ld keys reach it": "%ld/%ld anahtar ulaşıyor",
    "Set up": "Kur",
    "Setting up…": "Kuruluyor…",
    "Runs %@": "Çalıştırır: %@",
    "Connect %@ to %@": "%@ sırrını %@ ile bağla",
    "Update": "Güncelle",
    "Connect your vault": "Kasanı bağla",
    "Bitwarden Secrets Manager access token": "Bitwarden Secrets Manager erişim token'ı",
    "Paste a machine account's access token. passess keeps it in your keychain and uses it only to read the secrets you connect; agents never see it.": "Bir makine hesabının erişim token'ını yapıştır. passess onu anahtar zincirinde tutar ve yalnız bağladığın sırları okumak için kullanır; ajanlar onu hiç görmez.",
    "Access token": "Erişim token'ı",
    "store the token that opens your vault": "kasanı açan token'ı saklamak",
    "This copy of the app has no passess inside it, so it cannot take the token. Run `passess backend bws` in a terminal.": "Uygulamanın bu kopyasında passess yok, bu yüzden token'ı alamıyor. Bir terminalde `passess backend bws` çalıştır.",
    "Another passess build than yours, which it refuses: start it again": "Seninkinden farklı bir passess sürümü, komutlarını reddediyor: yeniden başlat",
]
