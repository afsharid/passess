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
    "Where may it be sent?": "Nereye gönderilebilir?",
    "passess http sends it only to these hosts. Separate them with commas. Empty: nowhere.":
        "passess http onu yalnız bu adreslere gönderir. Adresleri virgülle ayır. Boş bırakırsan hiçbir yere gitmez.",
    "%@ is not a host name such as api.github.com or *.example.com.":
        "%@ bir alan adı değil. Örnek: api.github.com ya da *.example.com.",
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
    "names no key, so it never asks passess": "anahtar adı yok, passess'e hiç sormuyor",
    "Pick the secret %@ sends on %@'s requests": "%@ uygulamasının %@ isteklerinde göndereceği sırrı seç",
    "No secrets in passess yet": "passess'te henüz sır yok",
    "Update": "Güncelle",
    "Connect your vault": "Kasanı bağla",
    "Bitwarden Secrets Manager access token": "Bitwarden Secrets Manager erişim token'ı",
    "Paste a machine account's access token. passess keeps it in your keychain and uses it only to read the secrets you connect; agents never see it.": "Bir makine hesabının erişim token'ını yapıştır. passess onu anahtar zincirinde tutar ve yalnız bağladığın sırları okumak için kullanır; ajanlar onu hiç görmez.",
    "Access token": "Erişim token'ı",
    "store the token that opens your vault": "kasanı açan token'ı saklamak",
    "Long: scroll to read all of it before you allow.": "Uzun: izin vermeden önce kaydırıp tamamını oku.",
    "This copy of the app has no passess inside it, so it cannot take the token. Run `passess backend bws` in a terminal.": "Uygulamanın bu kopyasında passess yok, bu yüzden token'ı alamıyor. Bir terminalde `passess backend bws` çalıştır.",
    "Another passess build than yours, which it refuses: start it again": "Seninkinden farklı bir passess sürümü, komutlarını reddediyor: yeniden başlat",
    // a config that does not load; adding from any backend
    "The config does not load": "Ayar dosyası yüklenmiyor",
    "Line %ld": "Satır %ld",
    "The config does not load: line %ld": "Ayar dosyası yüklenmiyor: satır %ld",
    "Open": "Aç",
    "Open the config to fix it": "Düzeltmek için ayar dosyasını aç",
    "used by %@": "kullanan: %@",
    "Write a reference such as op://vault/item/field or vault://path#key.": "op://kasa/öğe/alan ya da vault://yol#anahtar gibi bir referans yaz.",
    // the Add tab
    "Add": "Ekle",
    "Add a secret": "Sır ekle",
    "Add a secret from 1Password, the keychain or a reference": "1Password'den, anahtar zincirinden ya da bir referansla sır ekle",
    "Asking 1Password… it may ask you to unlock it.": "1Password'e soruluyor… kilidini açmanı isteyebilir.",
    "Choose a vault": "Bir kasa seç",
    "Filter items": "Öğeleri süz",
    "For 1Password, Vault, Bitwarden or bws: where the secret is, never the value.": "1Password, Vault, Bitwarden ya da bws için: sırrın yeri, asla değeri.",
    "From": "Kaynak",
    "From 1Password, the keychain or a reference": "1Password, anahtar zinciri ya da bir referans",
    "It goes to your login keychain; passess keeps only its name. Agents never see it.": "Giriş anahtar zincirine gider; passess yalnız adını tutar. Ajanlar onu hiç görmez.",
    "Keychain": "Anahtar zinciri",
    "Pick a field.": "Bir alan seç.",
    "Reference": "Referans",
    "This copy of the app has no passess inside it, so it cannot store a value. Run `passess add NAME --keychain` in a terminal.": "Uygulamanın bu kopyasında passess yok, bu yüzden değer saklayamıyor. Bir terminalde `passess add AD --keychain` çalıştır.",
    "Try again": "Yeniden dene",
    "Type the value.": "Değeri yaz.",
    "Value": "Değer",
    "Vault": "Kasa",
    // the agent at login
    "Could not change Start at Login": "Oturum açılınca başlatma değiştirilemedi",
    "Move Passess.app to /Applications and try again. A copy built with swift run has no agent to register.": "Passess.app'i /Applications klasörüne taşı ve yeniden dene. swift run ile derlenen kopyada kaydedilecek servis yok.",
    "Start the agent at login": "Servisi oturum açılınca başlat",
    "After a restart, secrets that ask first still work: the agent is there to ask.": "Yeniden başlattıktan sonra önce soran sırlar da çalışır: soracak servis hazırdır.",
    "Allow in System Settings": "Sistem Ayarları'nda izin ver",
    // first-run setup
    "%@ is a file of yours; passess leaves it alone.": "%@ senin bir dosyan; passess ona dokunmaz.",
    "Add another": "Bir tane daha ekle",
    "Add your first secret": "İlk sırrını ekle",
    "Check again": "Yeniden denetle",
    "Could not put passess on your PATH": "passess PATH'e konamadı",
    "Done": "Bitti",
    "Every coding agent found is set up.": "Bulunan her ajan kurulu.",
    "Find your password managers": "Parola yöneticilerini bul",
    "Five steps, no terminal. Each can be done again later.": "Beş adım, terminal yok. Her biri sonra yeniden yapılabilir.",
    "Link it": "Bağla",
    "Links ~/.local/bin/passess to the copy inside this app.": "~/.local/bin/passess'i bu uygulamanın içindeki kopyaya bağlar.",
    "No coding agent found on this Mac.": "Bu Mac'te ajan bulunamadı.",
    "None found yet: install 1Password's op, or add a secret to the keychain.": "Henüz bulunamadı: 1Password'ün op aracını kur ya da anahtar zincirine bir sır ekle.",
    "Put passess on your PATH": "passess'i PATH'e koy",
    "Ready: %@": "Hazır: %@",
    "Secrets that ask first keep working after a restart.": "Önce soran sırlar yeniden başlattıktan sonra da çalışır.",
    "Set up passess": "passess'i kur",
    "Set up runs passess install, after a backup.": "Kur düğmesi yedek aldıktan sonra passess install çalıştırır.",
    "Set up your coding agents": "Ajanlarını kur",
    "Setup": "Kurulum",
    "This copy of the app has no passess inside it: %@": "Uygulamanın bu kopyasında passess yok: %@",
    "Turn on": "Aç",
    "done": "tamam",
    "not done": "yapılmadı",

    // Settings window and problem buttons
    "passess settings": "passess ayarları",
    "Settings": "Ayarlar",
    "Backends, MCP servers, profiles and the agent": "Kasalar, MCP sunucuları, profiller ve servis",
    "MCP servers": "MCP sunucuları",
    "Profiles": "Profiller",
    "The passess command line tool is not installed.": "passess komut satırı aracı kurulu değil.",
    "Backends saved.": "Kasa ayarları kaydedildi.",
    "Kept in your keychain.": "Anahtar Zinciri'ne kaydedildi.",
    "This copy of the app has no passess inside it, so it cannot take the credential.":
        "Uygulamanın bu kopyasında passess yok, bu yüzden kimlik bilgisini alamaz.",
    "The account op uses. Empty: its default account.": "op'un kullandığı hesap. Boş: varsayılan hesap.",
    "Empty fields fall back to VAULT_ADDR and the system's certificates.":
        "Boş alanlar VAULT_ADDR'ı ve sistemin sertifikalarını kullanır.",
    "Namespace": "Ad alanı",
    "CA certificate file": "CA sertifika dosyası",
    "Token": "Token",
    "Token kept in the keychain; paste to replace": "Token Anahtar Zinciri'nde; değiştirmek için yapıştır",
    "Keep in keychain…": "Anahtar Zinciri'ne kaydet…",
    "Paste what `bw unlock --raw` prints. It lasts until bw locks again.":
        "`bw unlock --raw` çıktısını yapıştır. bw yeniden kilitlenene kadar geçerlidir.",
    "Session key": "Oturum anahtarı",
    "Session kept in the keychain; paste to replace": "Oturum Anahtar Zinciri'nde; değiştirmek için yapıştır",
    "A self-hosted server. Empty: bitwarden.com.": "Kendi sunucun. Boş: bitwarden.com.",
    "Coding agents start these servers through passess, which gives each one the secrets named here.":
        "Ajanlar bu sunucuları passess üzerinden başlatır; passess her birine burada adı geçen sırları verir.",
    "No MCP servers yet.": "Henüz MCP sunucusu yok.",
    "Secrets: %@": "Sırlar: %@",
    "Edit": "Düzenle",
    "Remove…": "Kaldır…",
    "Add a server": "Sunucu ekle",
    "Name": "Ad",
    "Local (a command)": "Yerel (bir komut)",
    "Remote (a URL)": "Uzak (bir URL)",
    "Headers": "Başlıklar",
    "One per line, NAME=TEMPLATE. Write a secret as {{NAME}}, never its value.":
        "Satır başına bir tane, AD=ŞABLON. Sırrı {{AD}} diye yaz, değerini asla yazma.",
    "Command": "Komut",
    "The program on the first line, then one argument per line.": "İlk satırda program, sonra her satırda bir argüman.",
    "One per line, VARIABLE=SECRET: the server gets the secret in that variable. Known: %@":
        "Satır başına bir tane, DEĞİŞKEN=SIR: sunucu sırrı o değişkende alır. Bilinenler: %@",
    "Plain variables": "Düz değişkenler",
    "One per line, VARIABLE=VALUE. Not for secrets.": "Satır başına bir tane, DEĞİŞKEN=DEĞER. Sırlar için değil.",
    "Their IDs, comma-separated (claude, codex). Empty: every one set up.":
        "Kimlikleri, virgülle ayrılmış (claude, codex). Boş: kurulu olanların hepsi.",
    "Redact the server's output": "Sunucunun çıktısını sansürle",
    "Saved. Set up your coding agents again to register it.": "Kaydedildi. Kaydetmek için ajanlarını yeniden kur.",
    "Removed. Set up your coding agents again to take it out.": "Kaldırıldı. Çıkarmak için ajanlarını yeniden kur.",
    "A profile gives a program a set of secrets: passess run NAME -- COMMAND.":
        "Profil bir programa bir grup sır verir: passess run AD -- KOMUT.",
    "No profiles yet.": "Henüz profil yok.",
    "Add a profile": "Profil ekle",
    "Programs": "Programlar",
    "The programs that may run under it, comma-separated (node, npm).": "Altında çalışabilecek programlar, virgülle ayrılmış (node, npm).",
    "Let a full-screen program have the terminal": "Tam ekran bir program terminali kullanabilsin",
    "Profile saved.": "Profil kaydedildi.",
    "Profile removed.": "Profil kaldırıldı.",
    "Keep resolved values for": "Çözülen değerleri sakla",
    "Durations such as 10m or 8h. 0 resolves every time.": "10m ya da 8h gibi süreler. 0: her seferinde yeniden çözer.",
    "An Allow lasts": "Bir izin geçerli kalır",
    "0 asks for every command.": "0: her komutta sorar.",
    "A question waits": "Bir soru bekler",
    "How long the agent waits for your answer before it refuses.": "Servisin reddetmeden önce cevabını ne kadar beklediği.",
    "Agent settings saved.": "Servis ayarları kaydedildi.",
    "Agent settings…": "Servis ayarları…",
    "Lock: forget values and approvals, keep running": "Kilitle: değerleri ve izinleri unut, çalışmaya devam et",
    "change how passess reaches your vault": "passess'in kasana nasıl ulaştığını değiştirmek",
    "store a credential that opens your vault": "kasanı açan bir kimlik bilgisini saklamak",
    "change which secrets an MCP server gets": "bir MCP sunucusunun hangi sırları alacağını değiştirmek",
    "remove an MCP server": "bir MCP sunucusunu kaldırmak",
    "change which secrets a program gets": "bir programın hangi sırları alacağını değiştirmek",
    "remove a profile": "bir profili kaldırmak",
    "change how long approvals last": "izinlerin ne kadar süreceğini değiştirmek",
    "Open the config": "Ayar dosyasını aç",
    "Make it private": "Yalnız bana açık yap",
    "Add it": "Ekle",
    "Install": "Kur",
    "Installing…": "Kuruluyor…",
    "Open 1Password": "1Password'ü aç",
    "Homebrew could not install %@.": "Homebrew %@ aracını kuramadı.",
]
