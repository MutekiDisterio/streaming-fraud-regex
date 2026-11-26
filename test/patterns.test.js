import { test } from 'node:test';
import assert from 'node:assert/strict';
import { patterns, scan, fraudScore } from '../src/patterns.js';

// [id, inputs that MUST match, inputs that must NOT match]
const cases = [
  ['email.disposable.mailinator', ['bob@mailinator.com', 'x@notmailinator.com'], ['bob@gmail.com', 'mailinator@company.com']],
  ['email.disposable.guerrilla', ['a@guerrillamail.com', 'a@sharklasers.com'], ['a@guerrilla.org', 'a@proton.me']],
  ['email.disposable.tenminute', ['a@10minutemail.com', 'a@20minutemail.it'], ['a@minute.com', 'a@mail.com']],
  ['email.disposable.tempmail', ['a@temp-mail.org', 'a@tempmail.com'], ['a@template.com', 'a@tmobile.com']],
  ['email.disposable.yopmail', ['a@yopmail.com', 'a@yopmail.fr'], ['a@yahoo.com', 'a@yop.com']],
  ['email.disposable.trash', ['a@trashmail.com', 'a@maildrop.cc'], ['a@trash.com', 'a@mail.ru']],
  ['email.plus_alias', ['maya+films@gmail.com'], ['maya.films@gmail.com']],
  ['email.gmail_dot_trick', ['m.a.y.a@gmail.com'], ['maya.k@gmail.com', 'm.a.y.a@outlook.com']],
  ['email.numeric_burst', ['user839201@gmail.com'], ['maya1994@gmail.com', 'maya@gmail.com']],
  ['email.keyboard_mash', ['qwerty77@gmail.com', 'asdasd@mail.com'], ['maya.k@gmail.com']],
  ['email.no_vowel_local', ['xkcdqwrtz@gmail.com'], ['maya@gmail.com', 'brt@gmail.com']],
  ['email.idn_punycode', ['a@xn--pple-43d.com'], ['a@apple.com']],
  ['ua.headless_chrome', ['Mozilla/5.0 HeadlessChrome/120.0.0.0 Safari/537.36'], ['Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36']],
  ['ua.phantomjs', ['Mozilla/5.0 PhantomJS/2.1.1'], ['Mozilla/5.0 Firefox/121.0']],
  ['ua.automation_framework', ['Mozilla/5.0 (Playwright) Chrome/120'], ['Mozilla/5.0 Chrome/120']],
  ['ua.curl_wget', ['curl/8.4.0', 'Wget/1.21'], ['Mozilla/5.0 curly']],
  ['ua.python_client', ['python-requests/2.31.0'], ['Mozilla/5.0 Python-loving browser']],
  ['ua.go_java_client', ['Go-http-client/1.1', 'okhttp/4.12.0'], ['Mozilla/5.0 Gecko']],
  ['ua.node_client', ['axios/1.6.2', 'node-fetch/3.0'], ['Mozilla/5.0 Safari/605.1.15']],
  ['ua.scraper_framework', ['Scrapy/2.11 (+https://scrapy.org)'], ['Mozilla/5.0 Chrome/120']],
  ['ua.empty_or_short', ['', 'Mozilla'], ['Mozilla/5.0 (iPhone)']],
  ['ua.outdated_chrome', ['Mozilla/5.0 Chrome/87.0.4280.88'], ['Mozilla/5.0 Chrome/131.0.0.0']],
  ['ref.self_loop', ['usr_89a42f_x89a42f'], ['usr_89a42f_k9Qx2b']],
  ['ref.sequential_token', ['usr_89a42f_tok0001', 'usr_89a42f_0004'], ['usr_89a42f_k9Qx2b']],
  ['ref.injection_chars', ["usr_89a42f_x' OR 1=1--", 'usr_<script>'], ['usr_89a42f_k9Qx2b']],
  ['net.datacenter_rdns', ['ec2-3-80-1-1.compute-1.amazonaws.com', 'static.88.1.2.3.your-server.de'], ['pool-71.verizon.net']],
  ['net.vpn_proxy_rdns', ['nl-ams-vpn12.example.net', 'tor-exit.relay.org'], ['vpnhub-lovers.com.example'.replace('vpnhub', 'film')]],
  ['net.xff_private_spoof', ['10.0.0.5, 203.0.113.7', '192.168.1.2'], ['203.0.113.7, 10.0.0.5', '172.32.0.1']],
  ['net.xff_long_chain', ['1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4'], ['1.1.1.1, 2.2.2.2']],
  ['play.zero_watch_time', ['film=88;watch_s=0;muted=0'], ['film=88;watch_s=0.5;muted=0', 'film=88;watch_s=120']],
  ['play.muted_hidden', ['muted=1;visible=0;watch_s=31', 'visible=0;muted=1'], ['muted=1;visible=1', 'muted=0;visible=0']],
  ['play.exact_threshold_stop', ['film=88;stop_at=30;rate=1', 'stop_at=30.0'], ['stop_at=300', 'stop_at=31']],
  ['play.no_input_events', ['input_events=0;watch_s=40'], ['input_events=10;watch_s=40']],
  ['play.tiny_viewport', ['viewport=1x1', 'viewport=0x480'], ['viewport=1920x1080', 'viewport=10x10']],
  ['play.impossible_rate', ['rate=4;watch_s=31', 'rate=16'], ['rate=1.5', 'rate=2']],
  ['pay.test_card_in_prod', ['4242424242424242'], ['4242424242424241']],
  ['pay.repeated_digits', ['1111111111111111'], ['4111111111111111']],
  ['pay.bin_cycling', ['424242******1231,424242******1232,424242******1233'], ['424242******1231,555555******9876']],
  ['pay.mismatched_country', ['card_country=US;amount=2.99;ip_country=VN'], ['card_country=US;amount=2.99;ip_country=US']],
];

test('library contains exactly 40 patterns with unique ids', () => {
  assert.equal(patterns.length, 40);
  assert.equal(new Set(patterns.map((p) => p.id)).size, 40);
});

test('every pattern except the inverted validator has positive and negative cases', () => {
  const covered = new Set(cases.map((c) => c[0]));
  for (const p of patterns) if (p.id !== 'ref.valid_format') assert.ok(covered.has(p.id), `missing cases for ${p.id}`);
});

for (const [id, yes, no] of cases) {
  test(id, () => {
    const p = patterns.find((x) => x.id === id);
    assert.ok(p, `unknown id ${id}`);
    for (const s of yes) assert.ok(p.regex.test(s), `${id} should match: ${s}`);
    for (const s of no) assert.ok(!p.regex.test(s), `${id} should NOT match: ${s}`);
  });
}

test('ref.valid_format (inverted): fires only for tampered tokens', () => {
  assert.deepEqual(scan('referral', 'usr_89a42f_k9Qx2b'), []);
  assert.ok(scan('referral', 'usr_89A42F_k9').includes('ref.valid_format'));
});

test('fraudScore: two medium signals cross the 80-point ban threshold', () => {
  const hits = [...scan('user_agent', 'Mozilla/5.0 HeadlessChrome/120.0'), ...scan('network', 'ec2-1-2-3-4.compute-1.amazonaws.com')];
  assert.ok(fraudScore(hits) >= 80);
});

test('fraudScore: a plus-alias alone stays below the suspicious threshold', () => {
  assert.ok(fraudScore(scan('email', 'maya+films@gmail.com')) < 50);
});
