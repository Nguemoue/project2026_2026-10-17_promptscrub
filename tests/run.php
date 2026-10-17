<?php
declare(strict_types=1);

require dirname(__DIR__) . '/promptscrub.php';

$failures = promptscrub_self_test();

function assert_same(mixed $expected, mixed $actual, string $name): void
{
    global $failures;
    if ($expected !== $actual) {
        $failures[] = $name . ' expected ' . var_export($expected, true) . ' got ' . var_export($actual, true);
    }
}

function assert_true(bool $value, string $name): void
{
    global $failures;
    if (!$value) {
        $failures[] = $name;
    }
}

function slice_between(string $html, string $start, string $end): string
{
    $from = strpos($html, $start);
    if ($from === false) {
        return '';
    }
    $from += strlen($start);
    $to = strpos($html, $end, $from);
    if ($to === false) {
        return '';
    }
    return substr($html, $from, $to - $from);
}

function run_cli(array $args, string $stdin = ''): array
{
    $cmd = array_merge([PHP_BINARY, dirname(__DIR__) . '/promptscrub.php'], $args);
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__));
    if (!is_resource($proc)) {
        return [127, '', 'proc_open failed'];
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), $stdout === false ? '' : $stdout, $stderr === false ? '' : $stderr];
}

[$code, $out, $err] = run_cli(['--self-test']);
assert_same(0, $code, 'cli self-test exit');
assert_true(str_contains($out, 'OK'), 'cli self-test output');

[$code, $out, $err] = run_cli(['--version']);
assert_same(0, $code, 'version exit');
assert_same(PROMPTSCRUB_VERSION . "\n", $out, 'version text');

[$code, $out, $err] = run_cli(['--rules']);
assert_same(0, $code, 'rules exit');
assert_true(str_contains($out, 'github_token'), 'rules list github');
assert_true(str_contains($out, 'env_secret'), 'rules list env');

[$code, $out, $err] = run_cli(['--nope']);
assert_same(1, $code, 'unknown option');

[$code, $out, $err] = run_cli(['missing-file.txt']);
assert_same(1, $code, 'missing file');

$secret = 'ghp_' . str_repeat('A', 36);
[$code, $out, $err] = run_cli(['--check', '--json'], "token $secret\n");
assert_same(2, $code, 'check json exit');
assert_true(!str_contains($out, $secret), 'json hides secret');
assert_true(!str_contains($err, $secret), 'stderr hides secret');
$json = json_decode($out, true);
assert_true(is_array($json) && ($json['findings_count'] ?? 0) === 1, 'json count');
assert_true(is_array($json) && str_contains((string) ($json['redacted'] ?? ''), '[REDACTED:github_token]'), 'json redacted');

[$code, $out, $err] = run_cli(['--check'], "hello ada@example.com\n");
assert_same(0, $code, 'check clean exit');
assert_true(str_contains($err, 'rien à masquer'), 'check clean summary');
assert_same('', $out, 'check suppresses body');

[$code, $out, $err] = run_cli(['--no-email'], "write ada@acme.io\n");
assert_same(0, $code, 'no-email exit');
assert_true(str_contains($out, 'ada@acme.io'), 'no-email keeps address');

$tmp = sys_get_temp_dir() . '/promptscrub-out-' . getmypid() . '.txt';
[$code, $out, $err] = run_cli(['-o', $tmp], "APP_KEY=base64:dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU\n");
assert_same(0, $code, 'output file exit');
$written = file_get_contents($tmp);
assert_true(is_string($written) && str_contains($written, '[REDACTED:env_secret]') && !str_contains($written, 'dGhpcy1pcy1qdXN0'), 'output file content');
@unlink($tmp);

$root = dirname(__DIR__);
[$code, $out, $err] = run_cli(['--check', $root . '/tests/fixtures']);
assert_same(2, $code, 'directory check exit');
assert_true(substr_count($err, 'env_secret') === 1, 'vendor fixture ignored, one secret');
assert_true(!str_contains($err, 'vendor-should-not-be-seen'), 'vendor value not echoed');

[$code, $out, $err] = run_cli(['-h']);
assert_same(0, $code, 'help exit');
assert_true(str_contains($out, '--check'), 'help mentions check');

[$status, $html] = promptscrub_handle_http('GET', []);
assert_same(200, $status, 'http get');
assert_true(str_contains($html, 'Masquer') && !str_contains($html, 'élément(s) masqué(s)'), 'get is a blank form');

[$status, $html] = promptscrub_handle_http('POST', ['action' => 'scrub', 'text' => '']);
assert_same(422, $status, 'http empty');

[$status, $html] = promptscrub_handle_http('PUT', []);
assert_same(405, $status, 'http put');

$xss = '"><script>alert(1)</script> APP_KEY=base64:dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU';
[$status, $html] = promptscrub_handle_http('POST', ['action' => 'scrub', 'text' => $xss]);
$outHtml = slice_between($html, 'id="out" readonly>', '</textarea>');
$encodedScript = htmlspecialchars('<script>', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
assert_same(200, $status, 'http scrub');
assert_true(!str_contains($html, '<script>'), 'xss escaped');
assert_true(str_contains($html, $encodedScript), 'xss visible as text');
assert_true(!str_contains($outHtml, 'dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU'), 'http hides app key');
assert_true(str_contains($outHtml, '[REDACTED:env_secret]'), 'http shows marker');

[$status, $html] = promptscrub_handle_http('POST', ['action' => 'sample', 'text' => 'IGNORED ada@elsewhere.io']);
$outHtml = slice_between($html, 'id="out" readonly>', '</textarea>');
$inHtml = slice_between($html, 'id="in" name="text"', '</textarea>');
assert_same(200, $status, 'http sample');
assert_true(str_contains($outHtml, 'db.internal') && !str_contains($outHtml, 's3cr3t-value'), 'sample redacts url password');
assert_true(!str_contains($inHtml, 'elsewhere.io'), 'sample ignores the posted textarea');

[$status, $html] = promptscrub_handle_http('POST', ['action' => 'scrub', 'text' => str_repeat('A', 1_000_001)]);
assert_same(413, $status, 'http too big');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " échec(s)\n");
    foreach ($failures as $failure) {
        fwrite(STDERR, "  - $failure\n");
    }
    exit(1);
}

fwrite(STDOUT, "tests : OK\n");
