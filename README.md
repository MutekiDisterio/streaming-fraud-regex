# streaming-fraud-regex

![tests](https://img.shields.io/badge/tests-44%20passing-brightgreen) ![patterns](https://img.shields.io/badge/patterns-40-orange) ![license](https://img.shields.io/badge/license-MIT-blue)

**40 tested regular expressions for fraud signals in streaming and referral programs:** disposable emails, bot user-agents, referral-token abuse, datacenter/VPN traffic, view inflation in player logs and card testing at checkout.

Built by the IndieStream trust & safety team (a student project for a marketing / growth-engineering course) to protect a two-sided referral program and creator payouts. Every pattern ships with positive *and* negative test cases.

> ⚠️ Each regex is a **signal, not a verdict**. Real users trip some of them (plus-aliases, shared Wi-Fi, old phones). Combine signals into a score and send borderline cases to manual review.

## Quick start

```bash
git clone <this repo> && cd streaming-fraud-regex
npm test          # node --test, zero dependencies
```

```js
import { scan, fraudScore } from './src/patterns.js';

const hits = [
  ...scan('email', 'user839201@temp-mail.org'),
  ...scan('user_agent', 'Mozilla/5.0 HeadlessChrome/120.0.0.0'),
  ...scan('playback', 'film=88;watch_s=31;muted=1;visible=0'),
];
// → ['email.disposable.tempmail', 'email.numeric_burst', 'ua.headless_chrome', 'play.muted_hidden']

fraudScore(hits); // 100 → reject (thresholds: ≥50 suspicious, ≥80 reject)
```

## Scoring model

| weight | points | meaning |
| --- | --- | --- |
| `critical` | 80 | near-certain fraud on its own (disposable inbox, test card in prod, injection) |
| `medium` | 45 | automation likely; **two medium signals = 90 → auto-reject** |
| `low` | 25 | weak alone; two lows = 50 → manual review, never an auto-ban |

## Patterns

### Email (full address) — 12

| id | weight | signal |
| --- | --- | --- |
| `email.disposable.mailinator` | critical | Mailinator family of disposable inboxes |
| `email.disposable.guerrilla` | critical | Guerrilla Mail domains |
| `email.disposable.tenminute` | critical | 10/20-minute mail services |
| `email.disposable.tempmail` | critical | temp-mail / tempmail variants |
| `email.disposable.yopmail` | critical | Yopmail and its alias domains |
| `email.disposable.trash` | critical | Trash/throwaway inbox brands |
| `email.plus_alias` | low | Sub-address tag (user+tag@) — common for honest users too |
| `email.gmail_dot_trick` | low | Gmail local part with 3+ dots (dots are ignored by Gmail) |
| `email.numeric_burst` | low | Short name followed by 5+ digits (bulk-generated accounts) |
| `email.keyboard_mash` | medium | Keyboard-walk local parts |
| `email.no_vowel_local` | medium | Local part of 8+ letters with no vowels (random strings) |
| `email.idn_punycode` | medium | Punycode domain (possible homograph lookalike) |

### User-Agent header — 10

| id | weight | signal |
| --- | --- | --- |
| `ua.headless_chrome` | medium | Headless Chrome |
| `ua.phantomjs` | medium | PhantomJS |
| `ua.automation_framework` | medium | Puppeteer / Playwright / Selenium markers |
| `ua.curl_wget` | medium | curl or wget |
| `ua.python_client` | medium | Python HTTP clients |
| `ua.go_java_client` | medium | Go / Java default HTTP clients |
| `ua.node_client` | medium | Node.js HTTP clients |
| `ua.scraper_framework` | medium | Scrapy and generic crawlers |
| `ua.empty_or_short` | low | Missing or suspiciously short UA (< 12 chars) |
| `ua.outdated_chrome` | low | Chrome major version below 100 (farms reuse old builds) |

### Referral token (`?ref=` value) — 4

| id | weight | signal |
| --- | --- | --- |
| `ref.valid_format` | low | INVERTED check: a valid token matches; NO match means a tampered token |
| `ref.self_loop` | critical | Token that embeds the referrer id twice (self-referral generator bug abuse) |
| `ref.sequential_token` | medium | Token suffix ends in an incrementing counter (scripted generation) |
| `ref.injection_chars` | critical | SQL/script injection characters inside a token |

### Network (reverse DNS / X-Forwarded-For) — 4

| id | weight | signal |
| --- | --- | --- |
| `net.datacenter_rdns` | medium | Reverse DNS of major cloud / hosting providers |
| `net.vpn_proxy_rdns` | medium | Hostnames that self-identify as VPN / proxy / Tor |
| `net.xff_private_spoof` | medium | Private or loopback IP at the start of X-Forwarded-For (header spoofing) |
| `net.xff_long_chain` | low | X-Forwarded-For chain with 4+ hops (proxy chaining) |

### Player heartbeat logs (`key=value;…`) — 6

| id | weight | signal |
| --- | --- | --- |
| `play.zero_watch_time` | low | Heartbeat reports a view with 0 seconds watched |
| `play.muted_hidden` | medium | Muted AND background tab (view inflation pattern) |
| `play.exact_threshold_stop` | medium | Playback stops at exactly 30s (the creator-payout view threshold) |
| `play.no_input_events` | low | Session with zero pointer/keyboard/touch events |
| `play.tiny_viewport` | medium | Player viewport of 1x1 or 0xN (hidden iframe stuffing) |
| `play.impossible_rate` | medium | Playback rate above 2x reported for a counted view |

### Payment / checkout logs — 4

| id | weight | signal |
| --- | --- | --- |
| `pay.test_card_in_prod` | critical | Well-known public test card numbers seen in production |
| `pay.repeated_digits` | medium | PAN made of one repeated digit |
| `pay.bin_cycling` | medium | Masked PAN log line showing the same BIN with sequential last-4 (card testing) |
| `pay.mismatched_country` | low | Checkout log where card country differs from IP country |

## Notes

- `ref.valid_format` is **inverted**: `scan()` reports it when a token does *not* match the expected format `usr_<6 alnum>_<6–32 alnum>`.
- Disposable-email patterns cover common brands only; pair them with a maintained blocklist for production.
- Lower-case emails before scanning; normalize Gmail (strip dots and `+tag`) before uniqueness checks.

## License

MIT — see [LICENSE](LICENSE).
