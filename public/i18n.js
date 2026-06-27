// --- Lightweight i18n layer -------------------------------------------------
// Loaded before index.js so `t()` is available globally. Covers the static UI
// and dynamic user-facing messages (status, alerts, progress). The technical
// cryptographic audit-log lines are intentionally left in English.

const I18N_STORAGE_KEY = 'vaultshare_lang';
const SUPPORTED_LANGS = ['en', 'tr'];

const translations = {
  en: {
    'meta.title': 'VaultShare | Highly Secure E2EE P2P File Transfer',
    'app.subtitle': 'End-to-End Encrypted (AES-GCM-256) P2P File Sharing',

    'badge.online': 'Online',
    'badge.offline': 'Offline',
    'badge.connecting': 'Connecting...',

    'setup.title': 'Establish Secure Channel',
    'setup.intro': 'To transfer files securely, create a new ephemeral room or join an existing one. All signaling traffic is encrypted and the final data connection is established directly peer-to-peer.',
    'setup.optionA': 'Option A: Create a Room',
    'setup.create': 'Generate Secret Room',
    'setup.or': 'OR',
    'setup.optionB': 'Option B: Join a Room',
    'setup.placeholder': 'Room ID (e.g. 529-194)',
    'setup.join': 'Join',
    'scan.button': 'Scan QR code',
    'scan.title': 'Scan room QR',
    'scan.hint': "Point the camera at the other device's room QR code.",
    'scan.cancel': 'Cancel',
    'scan.noCamera': 'Could not access the camera. Check browser permissions.',

    'conn.channelLabel': 'Secure Channel:',
    'conn.disconnect': 'Disconnect',
    'conn.qrHint': 'Let the other device scan this to join',
    'conn.verifyTitle': 'Security Verification Code',
    'conn.verifyDesc': 'Verify this code on both screens to ensure no Man-in-the-Middle interception is present.',
    'conn.verifyLabel': 'I have verified the security code on the other client',
    'verify.you': 'You verified',
    'verify.peer': 'Peer verified',

    'transfer.title': 'File Transfer',
    'transfer.dropMain': 'Drag & drop files here or <span>browse files</span>',
    'transfer.dropSub': 'Files are encrypted locally in-memory before leaving your device.',
    'transfer.clearAll': 'Clear all',
    'transfer.send': 'Send Encrypted Files',

    'chat.title': 'Secure Chat',
    'chat.desc': 'Messages are end-to-end encrypted and sent directly to your peer over the P2P channel.',
    'chat.placeholder': 'Type a message...',
    'chat.send': 'Send',
    'chat.you': 'You',
    'chat.peer': 'Peer',
    'notify.newMessage': 'New message from peer',

    'log.title': 'Cryptographic Security Audit Log',
    'log.clear': 'Clear Log',

    'footer.text': 'All encryption keys and data transfers are ephemeral. No files ever touch our servers.',
    'footer.privacy': 'Privacy Policy',

    'status.securing': 'Securing connection...',
    'status.keyExchange': 'Performing key exchange...',
    'status.fingerprintReady': 'Fingerprint code generated. Verify line security.',
    'status.tunnelActive': 'P2P Tunnel active',
    'status.bothVerified': 'Both peers verified — secure transfer ready.',
    'status.waitingPeerVerify': 'Waiting for peer to verify the security code...',
    'status.peerVerifiedConfirm': 'Peer verified. Confirm the code to enable transfers.',
    'status.verifyBoth': 'Verify the security code on both clients to continue.',
    'status.waitingOtherPeer': 'Waiting for the other peer to join this room...',
    'status.peerDisconnected': 'Peer disconnected. Waiting for peer to reconnect...',

    'progress.complete': 'Transfer Complete!',
    'progress.batchLabel': 'File {index}/{count}: ',
    'progress.checksum': 'Calculating SHA-256 checksum...',
    'progress.sendingMeta': 'Encrypting & sending metadata...',
    'progress.reassembling': 'Reassembling and verifying file...',
    'progress.downloadSuccess': 'Download Successful!',
    'progress.downloading': 'Downloading',
    'progress.transferring': 'Transferring',
    'progress.blocks': '{label} ({loaded}/{total} blocks)...',
    'progress.remaining': 'Remaining: {eta}s',

    'alert.serverError': 'Server error: {msg}',
    'alert.verifyBeforeSend': 'Please verify the security code with your peer before sending files.',
    'alert.peerNotVerified': 'Your peer has not verified the security code yet. Wait until they confirm before sending.',
    'alert.incomingVerify': 'A peer is trying to send you a file. Verify the security code to receive it.',
    'alert.checksumMismatch': 'Security Integrity Error: Checksum mismatch on "{name}"! Transfer aborted.',
    'alert.peerNotVerifiedAbort': 'Your peer has not verified the security code yet. Transfer aborted — ask them to verify, then send again.',
    'alert.invalidRoom': 'Please enter a valid Room ID.',
    'confirm.disconnect': 'Disconnect from current secure room?',
    'alert.cryptoUnavailable': 'Encryption unavailable: this app must be opened over HTTPS or via http://localhost. If you are testing across devices on a LAN IP, the browser disables the Web Crypto API on insecure origins, so the security code cannot be generated.',

    'files.summaryOne': '{count} file selected · {size}',
    'files.summaryMany': '{count} files selected · {size}',
    'files.removeAria': 'Remove file',
  },

  tr: {
    'meta.title': 'VaultShare | Üst Düzey Güvenli E2EE P2P Dosya Aktarımı',
    'app.subtitle': 'Uçtan Uca Şifreli (AES-GCM-256) Eşler Arası Dosya Paylaşımı',

    'badge.online': 'Çevrimiçi',
    'badge.offline': 'Çevrimdışı',
    'badge.connecting': 'Bağlanıyor...',

    'setup.title': 'Güvenli Kanal Kur',
    'setup.intro': 'Dosyaları güvenle aktarmak için yeni bir geçici oda oluşturun ya da var olan bir odaya katılın. Tüm sinyalleşme trafiği şifrelenir ve nihai veri bağlantısı doğrudan eşler arasında kurulur.',
    'setup.optionA': 'Seçenek A: Oda Oluştur',
    'setup.create': 'Gizli Oda Oluştur',
    'setup.or': 'VEYA',
    'setup.optionB': 'Seçenek B: Odaya Katıl',
    'setup.placeholder': 'Oda Kimliği (örn. 529-194)',
    'setup.join': 'Katıl',
    'scan.button': 'QR kodu tara',
    'scan.title': 'Oda QR kodunu tara',
    'scan.hint': 'Kamerayı diğer cihazın oda QR koduna doğrultun.',
    'scan.cancel': 'İptal',
    'scan.noCamera': 'Kameraya erişilemedi. Tarayıcı izinlerini kontrol edin.',

    'conn.channelLabel': 'Güvenli Kanal:',
    'conn.disconnect': 'Bağlantıyı Kes',
    'conn.qrHint': 'Katılmak için diğer cihaza bunu taratın',
    'conn.verifyTitle': 'Güvenlik Doğrulama Kodu',
    'conn.verifyDesc': 'Araya girme (MITM) saldırısı olmadığından emin olmak için bu kodu her iki ekranda da doğrulayın.',
    'conn.verifyLabel': 'Güvenlik kodunu diğer istemcide doğruladım',
    'verify.you': 'Siz doğruladınız',
    'verify.peer': 'Karşı taraf doğruladı',

    'transfer.title': 'Dosya Aktarımı',
    'transfer.dropMain': 'Dosyaları buraya sürükleyip bırakın ya da <span>dosyalara göz atın</span>',
    'transfer.dropSub': 'Dosyalar, cihazınızdan ayrılmadan önce bellekte yerel olarak şifrelenir.',
    'transfer.clearAll': 'Tümünü temizle',
    'transfer.send': 'Şifreli Dosyaları Gönder',

    'chat.title': 'Güvenli Sohbet',
    'chat.desc': 'Mesajlar uçtan uca şifrelenir ve P2P kanalı üzerinden doğrudan karşı tarafa gönderilir.',
    'chat.placeholder': 'Bir mesaj yazın...',
    'chat.send': 'Gönder',
    'chat.you': 'Siz',
    'chat.peer': 'Karşı taraf',
    'notify.newMessage': 'Karşı taraftan yeni mesaj',

    'log.title': 'Kriptografik Güvenlik Denetim Günlüğü',
    'log.clear': 'Günlüğü Temizle',

    'footer.text': 'Tüm şifreleme anahtarları ve veri aktarımları geçicidir. Hiçbir dosya sunucularımıza dokunmaz.',
    'footer.privacy': 'Gizlilik Politikası',

    'status.securing': 'Bağlantı güvenli hâle getiriliyor...',
    'status.keyExchange': 'Anahtar değişimi yapılıyor...',
    'status.fingerprintReady': 'Parmak izi kodu oluşturuldu. Hat güvenliğini doğrulayın.',
    'status.tunnelActive': 'P2P tüneli etkin',
    'status.bothVerified': 'Her iki taraf da doğrulandı — güvenli aktarım hazır.',
    'status.waitingPeerVerify': 'Karşı tarafın güvenlik kodunu doğrulaması bekleniyor...',
    'status.peerVerifiedConfirm': 'Karşı taraf doğrulandı. Aktarımları etkinleştirmek için kodu onaylayın.',
    'status.verifyBoth': 'Devam etmek için güvenlik kodunu her iki istemcide de doğrulayın.',
    'status.waitingOtherPeer': 'Karşı tarafın bu odaya katılması bekleniyor...',
    'status.peerDisconnected': 'Karşı tarafın bağlantısı kesildi. Yeniden bağlanması bekleniyor...',

    'progress.complete': 'Aktarım Tamamlandı!',
    'progress.batchLabel': 'Dosya {index}/{count}: ',
    'progress.checksum': 'SHA-256 sağlama toplamı hesaplanıyor...',
    'progress.sendingMeta': 'Üst veri şifrelenip gönderiliyor...',
    'progress.reassembling': 'Dosya yeniden birleştirilip doğrulanıyor...',
    'progress.downloadSuccess': 'İndirme Başarılı!',
    'progress.downloading': 'İndiriliyor',
    'progress.transferring': 'Aktarılıyor',
    'progress.blocks': '{label} ({loaded}/{total} blok)...',
    'progress.remaining': 'Kalan: {eta}sn',

    'alert.serverError': 'Sunucu hatası: {msg}',
    'alert.verifyBeforeSend': 'Lütfen dosyaları göndermeden önce güvenlik kodunu karşı tarafla doğrulayın.',
    'alert.peerNotVerified': 'Karşı taraf güvenlik kodunu henüz doğrulamadı. Göndermeden önce onaylamasını bekleyin.',
    'alert.incomingVerify': 'Karşı taraf size dosya göndermeye çalışıyor. Almak için güvenlik kodunu doğrulayın.',
    'alert.checksumMismatch': 'Güvenlik Bütünlüğü Hatası: "{name}" dosyasında sağlama toplamı uyuşmuyor! Aktarım iptal edildi.',
    'alert.peerNotVerifiedAbort': 'Karşı taraf güvenlik kodunu henüz doğrulamadı. Aktarım iptal edildi — doğrulamasını isteyin, sonra yeniden gönderin.',
    'alert.invalidRoom': 'Lütfen geçerli bir Oda Kimliği girin.',
    'confirm.disconnect': 'Geçerli güvenli odadan bağlantı kesilsin mi?',
    'alert.cryptoUnavailable': 'Şifreleme kullanılamıyor: bu uygulama HTTPS üzerinden ya da http://localhost ile açılmalıdır. Cihazlar arası bir LAN IP\'sinde test ediyorsanız, tarayıcı güvenli olmayan kaynaklarda Web Crypto API\'sini devre dışı bırakır, bu yüzden güvenlik kodu oluşturulamaz.',

    'files.summaryOne': '{count} dosya seçildi · {size}',
    'files.summaryMany': '{count} dosya seçildi · {size}',
    'files.removeAria': 'Dosyayı kaldır',
  },
};

function detectInitialLang() {
  const stored = localStorage.getItem(I18N_STORAGE_KEY);
  if (stored && SUPPORTED_LANGS.includes(stored)) return stored;
  const nav = (navigator.language || 'en').toLowerCase();
  return nav.startsWith('tr') ? 'tr' : 'en';
}

let currentLang = detectInitialLang();

// Translate a key, interpolating {placeholder} tokens from params. Falls back to
// English, then to the raw key, so a missing translation never breaks the UI.
function t(key, params) {
  const dict = translations[currentLang] || translations.en;
  let str = dict[key];
  if (str === undefined) str = translations.en[key];
  if (str === undefined) return key;
  if (params) {
    str = str.replace(/\{(\w+)\}/g, (m, name) =>
      Object.prototype.hasOwnProperty.call(params, name) ? params[name] : m
    );
  }
  return str;
}

// Apply translations to all statically-marked elements in the DOM.
function applyStaticTranslations() {
  document.documentElement.lang = currentLang;
  document.title = t('meta.title');

  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    el.innerHTML = t(el.getAttribute('data-i18n-html'));
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
    el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria-label')));
  });
  // Point links at the current language's page: "<base>.html" for English,
  // "<base>.<lang>.html" otherwise (e.g. privacy-policy.tr.html).
  document.querySelectorAll('[data-i18n-localized-href]').forEach((el) => {
    const base = el.getAttribute('data-i18n-localized-href');
    el.setAttribute('href', currentLang === 'en' ? `${base}.html` : `${base}.${currentLang}.html`);
  });

  // Reflect the active language on the switcher buttons.
  document.querySelectorAll('.lang-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === currentLang);
  });
}

function getLang() {
  return currentLang;
}

function setLang(lang) {
  if (!SUPPORTED_LANGS.includes(lang) || lang === currentLang) return;
  currentLang = lang;
  localStorage.setItem(I18N_STORAGE_KEY, lang);
  applyStaticTranslations();
  // Let index.js re-render any state-derived dynamic text in the new language.
  window.dispatchEvent(new CustomEvent('vaultshare:langchange', { detail: { lang } }));
}

// Wire the language switcher and apply initial translations on load.
window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.lang-btn').forEach((btn) => {
    btn.addEventListener('click', () => setLang(btn.getAttribute('data-lang')));
  });
  applyStaticTranslations();
});

// Expose for index.js
window.t = t;
window.I18N = { t, getLang, setLang, applyStaticTranslations };
