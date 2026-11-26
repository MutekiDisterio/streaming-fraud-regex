// streaming-fraud-regex — tested regular expressions for streaming & referral fraud signals.
// Each pattern is a HEURISTIC signal, not a verdict: combine signals into a score (see README).
// License: MIT

/** @typedef {{ id: string, category: string, regex: RegExp, weight: 'low'|'medium'|'critical', description: string }} Pattern */

/** @type {Pattern[]} */
export const patterns = [
  // ── EMAIL (applied to the full email address, lower-cased) ─────────────────
  { id: 'email.disposable.mailinator', category: 'email', weight: 'critical', description: 'Mailinator family of disposable inboxes', regex: /@(?:mailinator|mailinater|mailinator2|reallymymail|sogetthis|suremail|notmailinator)\.(?:com|net|info)$/i },
  { id: 'email.disposable.guerrilla', category: 'email', weight: 'critical', description: 'Guerrilla Mail domains', regex: /@(?:guerrillamail(?:block)?|sharklasers|grr|pokemail|spam4)\.(?:com|net|org|info|biz|de|me)$/i },
  { id: 'email.disposable.tenminute', category: 'email', weight: 'critical', description: '10/20-minute mail services', regex: /@(?:10|20|30)minute(?:mail|email)\.[a-z.]{2,6}$/i },
  { id: 'email.disposable.tempmail', category: 'email', weight: 'critical', description: 'temp-mail / tempmail variants', regex: /@(?:temp-?mail|tempmailo|tempr|tmpmail|tmail)\.[a-z.]{2,6}$/i },
  { id: 'email.disposable.yopmail', category: 'email', weight: 'critical', description: 'Yopmail and its alias domains', regex: /@(?:yopmail\.(?:com|fr|net)|cool\.fr\.nf|jetable\.fr\.nf|courriel\.fr\.nf)$/i },
  { id: 'email.disposable.trash', category: 'email', weight: 'critical', description: 'Trash/throwaway inbox brands', regex: /@(?:trashmail|trash-mail|throwawaymail|throwam|maildrop|getnada|dispostable|mintemail|fakeinbox)\.[a-z.]{2,6}$/i },
  { id: 'email.plus_alias', category: 'email', weight: 'low', description: 'Sub-address tag (user+tag@) — common for honest users too', regex: /^[^@+\s]+\+[^@\s]*@/ },
  { id: 'email.gmail_dot_trick', category: 'email', weight: 'low', description: 'Gmail local part with 3+ dots (dots are ignored by Gmail)', regex: /^(?:[^@.\s]+\.){3,}[^@.\s]+@(?:gmail|googlemail)\.com$/i },
  { id: 'email.numeric_burst', category: 'email', weight: 'low', description: 'Short name followed by 5+ digits (bulk-generated accounts)', regex: /^[a-z]{2,8}\d{5,}@/i },
  { id: 'email.keyboard_mash', category: 'email', weight: 'medium', description: 'Keyboard-walk local parts', regex: /^[^@]*(?:qwert|asdfg|zxcvb|qazwsx|12345|asdasd)[^@]*@/i },
  { id: 'email.no_vowel_local', category: 'email', weight: 'medium', description: 'Local part of 8+ letters with no vowels (random strings)', regex: /^[b-df-hj-np-tv-z]{8,}@/i },
  { id: 'email.idn_punycode', category: 'email', weight: 'medium', description: 'Punycode domain (possible homograph lookalike)', regex: /@(?:[a-z0-9-]+\.)*xn--[a-z0-9-]+\.[a-z]{2,}$/i },

  // ── USER-AGENT (applied to the raw User-Agent header) ──────────────────────
  { id: 'ua.headless_chrome', category: 'user_agent', weight: 'medium', description: 'Headless Chrome', regex: /HeadlessChrome\//i },
  { id: 'ua.phantomjs', category: 'user_agent', weight: 'medium', description: 'PhantomJS', regex: /PhantomJS\//i },
  { id: 'ua.automation_framework', category: 'user_agent', weight: 'medium', description: 'Puppeteer / Playwright / Selenium markers', regex: /\b(?:Puppeteer|Playwright|Selenium|WebDriver|Cypress)\b/i },
  { id: 'ua.curl_wget', category: 'user_agent', weight: 'medium', description: 'curl or wget', regex: /^(?:curl|Wget)\/\d/i },
  { id: 'ua.python_client', category: 'user_agent', weight: 'medium', description: 'Python HTTP clients', regex: /\b(?:python-requests|python-urllib|aiohttp|httpx)\/\d/i },
  { id: 'ua.go_java_client', category: 'user_agent', weight: 'medium', description: 'Go / Java default HTTP clients', regex: /^(?:Go-http-client|Java|Apache-HttpClient|okhttp)\/\d/i },
  { id: 'ua.node_client', category: 'user_agent', weight: 'medium', description: 'Node.js HTTP clients', regex: /\b(?:axios|node-fetch|undici|got)\/\d/i },
  { id: 'ua.scraper_framework', category: 'user_agent', weight: 'medium', description: 'Scrapy and generic crawlers', regex: /\b(?:Scrapy|crawler|spider|scraper)\b/i },
  { id: 'ua.empty_or_short', category: 'user_agent', weight: 'low', description: 'Missing or suspiciously short UA (< 12 chars)', regex: /^.{0,11}$/s },
  { id: 'ua.outdated_chrome', category: 'user_agent', weight: 'low', description: 'Chrome major version below 100 (farms reuse old builds)', regex: /\bChrome\/(?:[1-9]|[1-9]\d)\.\d/ },

  // ── REFERRAL TOKENS (applied to the ?ref= value, format: usr_<6 alnum>_<token>) ──
  { id: 'ref.valid_format', category: 'referral', weight: 'low', description: 'INVERTED check: a valid token matches; NO match means a tampered token', regex: /^usr_[a-z0-9]{6}_[A-Za-z0-9]{6,32}$/ },
  { id: 'ref.self_loop', category: 'referral', weight: 'critical', description: 'Token that embeds the referrer id twice (self-referral generator bug abuse)', regex: /^usr_([a-z0-9]{6})_.*\1/ },
  { id: 'ref.sequential_token', category: 'referral', weight: 'medium', description: 'Token suffix ends in an incrementing counter (scripted generation)', regex: /_[A-Za-z]{0,8}0{3,}\d{1,3}$/ },
  { id: 'ref.injection_chars', category: 'referral', weight: 'critical', description: 'SQL/script injection characters inside a token', regex: /['"<>;`]|--|\/\*/ },

  // ── NETWORK (applied to reverse-DNS hostname or X-Forwarded-For header) ───
  { id: 'net.datacenter_rdns', category: 'network', weight: 'medium', description: 'Reverse DNS of major cloud / hosting providers', regex: /\.(?:amazonaws\.com|googleusercontent\.com|cloudapp\.azure\.com|linodeusercontent\.com|digitaloceanspaces\.com|your-server\.de|ovh\.net|vultrusercontent\.com)$/i },
  { id: 'net.vpn_proxy_rdns', category: 'network', weight: 'medium', description: 'Hostnames that self-identify as VPN / proxy / Tor', regex: /(?:^|[.-])(?:vpn|proxy|tor-?exit|exit-?node)(?:[.-]|\d)/i },
  { id: 'net.xff_private_spoof', category: 'network', weight: 'medium', description: 'Private or loopback IP at the start of X-Forwarded-For (header spoofing)', regex: /^\s*(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/ },
  { id: 'net.xff_long_chain', category: 'network', weight: 'low', description: 'X-Forwarded-For chain with 4+ hops (proxy chaining)', regex: /^(?:[^,]+,){3,}[^,]+$/ },

  // ── PLAYBACK (applied to player heartbeat log lines: key=value;key=value) ──
  { id: 'play.zero_watch_time', category: 'playback', weight: 'low', description: 'Heartbeat reports a view with 0 seconds watched', regex: /(?:^|;)watch_s=0(?:;|$)/ },
  { id: 'play.muted_hidden', category: 'playback', weight: 'medium', description: 'Muted AND background tab (view inflation pattern)', regex: /(?=.*(?:^|;)muted=1(?:;|$))(?=.*(?:^|;)visible=0(?:;|$))/ },
  { id: 'play.exact_threshold_stop', category: 'playback', weight: 'medium', description: 'Playback stops at exactly 30s (the creator-payout view threshold)', regex: /(?:^|;)stop_at=30(?:\.0+)?(?:;|$)/ },
  { id: 'play.no_input_events', category: 'playback', weight: 'low', description: 'Session with zero pointer/keyboard/touch events', regex: /(?:^|;)input_events=0(?:;|$)/ },
  { id: 'play.tiny_viewport', category: 'playback', weight: 'medium', description: 'Player viewport of 1x1 or 0xN (hidden iframe stuffing)', regex: /(?:^|;)viewport=(?:0x\d+|\d+x0|1x1)(?:;|$)/ },
  { id: 'play.impossible_rate', category: 'playback', weight: 'medium', description: 'Playback rate above 2x reported for a counted view', regex: /(?:^|;)rate=(?:[3-9]|\d{2,})(?:\.\d+)?(?:;|$)/ },

  // ── PAYMENT (applied to card BIN / masked PAN strings in checkout logs) ────
  { id: 'pay.test_card_in_prod', category: 'payment', weight: 'critical', description: 'Well-known public test card numbers seen in production', regex: /^(?:4242424242424242|4000056655665556|5555555555554444|2223003122003222|378282246310005)$/ },
  { id: 'pay.repeated_digits', category: 'payment', weight: 'medium', description: 'PAN made of one repeated digit', regex: /^(\d)\1{11,18}$/ },
  { id: 'pay.bin_cycling', category: 'payment', weight: 'medium', description: 'Masked PAN log line showing the same BIN with sequential last-4 (card testing)', regex: /^(\d{6})\*+(\d{3})[0-9](?:,\1\*+\2[0-9]){2,}$/ },
  { id: 'pay.mismatched_country', category: 'payment', weight: 'low', description: 'Checkout log where card country differs from IP country', regex: /card_country=([A-Z]{2});.*ip_country=(?!\1)[A-Z]{2}/ },
];

export const byCategory = (cat) => patterns.filter((p) => p.category === cat);

/** Returns matched pattern ids. ref.valid_format is inverted: it fires when the token does NOT match. */
export function scan(category, input) {
  const s = String(input ?? '');
  return byCategory(category)
    .filter((p) => (p.id === 'ref.valid_format' ? !p.regex.test(s) : p.regex.test(s)))
    .map((p) => p.id);
}

const POINTS = { low: 25, medium: 45, critical: 80 };
/** Simple Fraud_Score aggregation: sum of points, capped at 100 (thresholds: 50 suspicious, 80 reject). */
export function fraudScore(hits) {
  const total = hits.reduce((acc, id) => acc + POINTS[patterns.find((p) => p.id === id).weight], 0);
  return Math.min(total, 100);
}
