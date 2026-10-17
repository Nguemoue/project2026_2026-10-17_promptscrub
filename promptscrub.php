#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * PromptScrub — masque secrets et données perso avant un copier-coller.
 *
 * Un seul fichier, zéro dépendance, PHP >= 8.1.
 *   php promptscrub.php --help
 */

if (defined('PROMPTSCRUB_LOADED')) {
    return;
}
define('PROMPTSCRUB_LOADED', true);

const PROMPTSCRUB_VERSION = '1.0.0';

/**
 * @param array{email?:bool,iban?:bool,cards?:bool} $options
 * @return array{
 *   redacted:string,
 *   findings:list<array{rule:string,label:string,line:int}>,
 *   counts:array<string,int>
 * }
 */
function promptscrub_scrub(string $text, array $options = []): array
{
    $options = array_merge(['email' => true, 'iban' => true, 'cards' => true], $options);
    $spans = [];
    promptscrub_scan_private_keys($text, $spans);
    promptscrub_scan_tokens($text, $spans);
    promptscrub_scan_jwt($text, $spans);
    promptscrub_scan_http_auth($text, $spans);
    promptscrub_scan_url_passwords($text, $spans);
    if ($options['cards']) {
        promptscrub_scan_cards($text, $spans);
    }
    if ($options['iban']) {
        promptscrub_scan_ibans($text, $spans);
    }
    promptscrub_scan_env_secrets($text, $spans);
    if ($options['email']) {
        promptscrub_scan_emails($text, $spans);
    }

    $accepted = promptscrub_resolve_overlaps($spans);
    $redacted = $text;
    $built = '';
    $cursor = 0;
    $findings = [];
    $counts = [];
    foreach ($accepted as $span) {
        $built .= substr($redacted, $cursor, $span['start'] - $cursor);
        $built .= $span['replacement'];
        $cursor = $span['end'];
        $findings[] = [
            'rule' => $span['rule'],
            'label' => $span['label'],
            'line' => promptscrub_line_at($text, $span['start']),
        ];
        $counts[$span['rule']] = ($counts[$span['rule']] ?? 0) + 1;
    }
    $built .= substr($redacted, $cursor);

    return [
        'redacted' => $built,
        'findings' => $findings,
        'counts' => $counts,
    ];
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $spans
 * @return list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}>
 */
function promptscrub_resolve_overlaps(array $spans): array
{
    usort($spans, static function (array $a, array $b): int {
        if ($a['priority'] !== $b['priority']) {
            return $a['priority'] <=> $b['priority'];
        }
        $len = ($b['end'] - $b['start']) <=> ($a['end'] - $a['start']);
        if ($len !== 0) {
            return $len;
        }
        return $a['start'] <=> $b['start'];
    });

    $chosen = [];
    foreach ($spans as $span) {
        if ($span['end'] <= $span['start']) {
            continue;
        }
        $overlap = false;
        foreach ($chosen as $kept) {
            if ($span['start'] < $kept['end'] && $span['end'] > $kept['start']) {
                $overlap = true;
                break;
            }
        }
        if (!$overlap) {
            $chosen[] = $span;
        }
    }
    usort($chosen, static fn (array $a, array $b): int => $a['start'] <=> $b['start']);
    return $chosen;
}

function promptscrub_line_at(string $text, int $offset): int
{
    if ($offset <= 0) {
        return 1;
    }
    $offset = min($offset, strlen($text));
    return substr_count($text, "\n", 0, $offset) + 1;
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_push_span(array &$out, int $start, int $end, string $rule, string $label, int $priority): void
{
    if ($end <= $start) {
        return;
    }
    $out[] = [
        'start' => $start,
        'end' => $end,
        'replacement' => '[REDACTED:' . $rule . ']',
        'rule' => $rule,
        'label' => $label,
        'priority' => $priority,
    ];
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_private_keys(string $text, array &$out): void
{
    $paired = '/-----BEGIN ' . '[A-Z0-9 ]{0,40}' . 'PRIVATE KEY-----'
        . '.*?'
        . '-----END ' . '[A-Z0-9 ]{0,40}' . 'PRIVATE KEY-----/s';
    promptscrub_scan_pattern($text, $paired, 'private_key', 'PEM private key', 10, $out, null);

    $open = '/-----BEGIN ' . '[A-Z0-9 ]{0,40}' . 'PRIVATE KEY-----/';
    if (!preg_match_all($open, $text, $matches, PREG_OFFSET_CAPTURE)) {
        return;
    }
    foreach ($matches[0] as $match) {
        promptscrub_push_span($out, $match[1], strlen($text), 'private_key', 'PEM private key', 12);
    }
}

/**
 * @return list<array{0:string,1:string,2:string,3:int}>
 */
function promptscrub_token_patterns(): array
{
    return [
        ['aws_access_key_id', 'AWS access key id', '/\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z0-9]{16}\b/', 20],
        ['github_token', 'GitHub token', '/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/', 20],
        ['github_token', 'GitHub token', '/\bgithub_pat_[A-Za-z0-9_]{20,255}\b/', 20],
        ['gitlab_token', 'GitLab token', '/\bglpat-[A-Za-z0-9\-_]{20,255}\b/', 20],
        ['slack_token', 'Slack token', '/\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/', 20],
        ['slack_webhook', 'Slack webhook', '#\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+#', 20],
        ['stripe_secret_key', 'Stripe secret key', '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,255}\b/', 20],
        ['anthropic_key', 'Anthropic API key', '/\bsk-ant-[A-Za-z0-9\-_]{20,255}\b/', 18],
        ['openai_key', 'OpenAI API key', '/\bsk-[A-Za-z0-9\-_]{20,255}\b/', 22],
        ['xai_key', 'xAI API key', '/\bxai-[A-Za-z0-9\-_]{20,255}\b/', 20],
        ['groq_key', 'Groq API key', '/\bgsk_[A-Za-z0-9]{20,255}\b/', 20],
        ['google_api_key', 'Google API key', '/\bAIza[0-9A-Za-z\-_]{35}\b/', 20],
        ['sendgrid_key', 'SendGrid API key', '/\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/', 20],
        ['npm_token', 'npm access token', '/\bnpm_[A-Za-z0-9]{36}\b/', 20],
        ['pypi_token', 'PyPI token', '/\bpypi-[A-Za-z0-9\-_]{50,255}\b/', 20],
        ['shopify_token', 'Shopify token', '/\bshp(?:at|ss|ca|pa)_[A-Za-z0-9]{16,255}\b/', 20],
        ['huggingface_token', 'Hugging Face token', '/\bhf_[A-Za-z0-9]{30,255}\b/', 20],
        ['discord_webhook', 'Discord webhook', '#\bhttps://(?:discord(?:app)?\.com)/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}#', 20],
    ];
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_tokens(string $text, array &$out): void
{
    foreach (promptscrub_token_patterns() as [$rule, $label, $pattern, $priority]) {
        promptscrub_scan_pattern($text, $pattern, $rule, $label, $priority, $out, null);
    }

    $awsSecret = '/(?i)\b(?:aws_secret_access_key|aws_secret_key|aws_secret)\b\s*[=:]\s*[\'"]?([A-Za-z0-9\/+=]{40})/';
    promptscrub_scan_pattern($text, $awsSecret, 'aws_secret_access_key', 'AWS secret access key', 20, $out, static function (array $match): ?array {
        $value = $match[1];
        return [$value[1], $value[1] + strlen($value[0])];
    });
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 * @param null|callable(array):?array{0:int,1:int} $spanOf
 */
function promptscrub_scan_pattern(string $text, string $pattern, string $rule, string $label, int $priority, array &$out, ?callable $spanOf): void
{
    $found = preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
    if ($found === false) {
        throw new RuntimeException('Invalid detector pattern for ' . $rule . ' (PCRE ' . preg_last_error() . ')');
    }
    if ($found === 0) {
        return;
    }
    foreach ($matches as $match) {
        if ($spanOf !== null) {
            $span = $spanOf($match);
            if ($span === null) {
                continue;
            }
            [$start, $end] = $span;
        } else {
            $start = $match[0][1];
            $end = $start + strlen($match[0][0]);
        }
        promptscrub_push_span($out, $start, $end, $rule, $label, $priority);
    }
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_jwt(string $text, array &$out): void
{
    $pattern = '/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/';
    promptscrub_scan_pattern($text, $pattern, 'jwt', 'JSON Web Token', 30, $out, static function (array $match): ?array {
        $token = $match[0][0];
        if (!promptscrub_looks_like_jwt($token)) {
            return null;
        }
        return [$match[0][1], $match[0][1] + strlen($token)];
    });
}

function promptscrub_looks_like_jwt(string $token): bool
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }
    $header = promptscrub_b64url_decode($parts[0]);
    if ($header === null) {
        return false;
    }
    $json = json_decode($header, true);
    return is_array($json) && isset($json['alg']) && is_string($json['alg']) && $json['alg'] !== '';
}

function promptscrub_b64url_decode(string $value): ?string
{
    $value = strtr($value, '-_', '+/');
    $pad = strlen($value) % 4;
    if ($pad > 0) {
        $value .= str_repeat('=', 4 - $pad);
    }
    $decoded = base64_decode($value, true);
    return $decoded === false ? null : $decoded;
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_http_auth(string $text, array &$out): void
{
    promptscrub_scan_pattern(
        $text,
        '/(?i)\bBearer\s+([A-Za-z0-9\-._~+\/=]{16,})/',
        'bearer_token',
        'Bearer token',
        40,
        $out,
        static function (array $match): array {
            return [$match[1][1], $match[1][1] + strlen($match[1][0])];
        }
    );
    promptscrub_scan_pattern(
        $text,
        '/(?i)\bBasic\s+([A-Za-z0-9+\/=]{16,})/',
        'basic_auth',
        'HTTP Basic credential',
        40,
        $out,
        static function (array $match): ?array {
            $decoded = base64_decode($match[1][0], true);
            if ($decoded === false || !str_contains($decoded, ':')) {
                return null;
            }
            return [$match[1][1], $match[1][1] + strlen($match[1][0])];
        }
    );
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_url_passwords(string $text, array &$out): void
{
    $pattern = '#(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:\s/@]*):(?P<pass>[^@\s/]+)@#';
    promptscrub_scan_pattern($text, $pattern, 'url_password', 'Password embedded in a URL', 50, $out, static function (array $match): ?array {
        $scheme = strtolower($match['scheme'][0]);
        if ($scheme === 'mailto:') {
            return null;
        }
        $pass = $match['pass'][0];
        if (strlen($pass) < 3 || promptscrub_is_placeholder($pass)) {
            return null;
        }
        return [$match['pass'][1], $match['pass'][1] + strlen($pass)];
    });
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_cards(string $text, array &$out): void
{
    $grouped = '/\b(?:\d{4}[ -]){3}\d{4}\b|\b\d{4}[ -]\d{6}[ -]\d{5}\b/';
    promptscrub_scan_pattern($text, $grouped, 'payment_card', 'Payment card number', 60, $out, static function (array $match): ?array {
        if (!promptscrub_luhn_ok($match[0][0])) {
            return null;
        }
        return [$match[0][1], $match[0][1] + strlen($match[0][0])];
    });

    $withKeyword = '/(?i)\b(?:card(?:\s*number)?|visa|mastercard|amex|pan)\b[^0-9]{0,24}(\d{13,19})\b/';
    promptscrub_scan_pattern($text, $withKeyword, 'payment_card', 'Payment card number', 60, $out, static function (array $match): ?array {
        if (!promptscrub_luhn_ok($match[1][0])) {
            return null;
        }
        return [$match[1][1], $match[1][1] + strlen($match[1][0])];
    });
}

function promptscrub_luhn_ok(string $raw): bool
{
    $digits = preg_replace('/\D/', '', $raw) ?? '';
    $length = strlen($digits);
    if ($length < 13 || $length > 19) {
        return false;
    }
    $first = $digits[0];
    if ($first !== '3' && $first !== '4' && $first !== '5' && $first !== '6') {
        return false;
    }
    if (preg_match('/^(\d)\1+$/', $digits) === 1) {
        return false;
    }
    $sum = 0;
    $double = false;
    for ($i = $length - 1; $i >= 0; $i--) {
        $n = (int) $digits[$i];
        if ($double) {
            $n *= 2;
            if ($n > 9) {
                $n -= 9;
            }
        }
        $sum += $n;
        $double = !$double;
    }
    return $sum % 10 === 0;
}

/**
 * @return array<string,int>
 */
function promptscrub_iban_lengths(): array
{
    return [
        'AL' => 28, 'AD' => 24, 'AT' => 20, 'AZ' => 28, 'BH' => 22, 'BE' => 16, 'BA' => 20,
        'BR' => 29, 'BG' => 22, 'CR' => 22, 'HR' => 21, 'CY' => 28, 'CZ' => 24, 'DK' => 18,
        'DO' => 28, 'EE' => 20, 'FO' => 18, 'FI' => 18, 'FR' => 27, 'GE' => 22, 'DE' => 22,
        'GI' => 23, 'GR' => 27, 'GL' => 18, 'GT' => 28, 'HU' => 28, 'IS' => 26, 'IE' => 22,
        'IL' => 23, 'IT' => 27, 'JO' => 30, 'KZ' => 20, 'KW' => 30, 'LV' => 21, 'LB' => 28,
        'LI' => 21, 'LT' => 20, 'LU' => 20, 'MK' => 19, 'MT' => 31, 'MR' => 27, 'MU' => 30,
        'MC' => 27, 'MD' => 24, 'ME' => 22, 'NL' => 18, 'NO' => 15, 'PK' => 24, 'PS' => 29,
        'PL' => 28, 'PT' => 25, 'QA' => 29, 'RO' => 24, 'SM' => 27, 'SA' => 24, 'RS' => 22,
        'SK' => 24, 'SI' => 19, 'ES' => 24, 'SE' => 24, 'CH' => 21, 'TN' => 24, 'TR' => 26,
        'AE' => 23, 'GB' => 22, 'VA' => 22, 'VG' => 24, 'UA' => 29, 'XK' => 20, 'EG' => 29,
        'SV' => 28, 'TL' => 23, 'IQ' => 23, 'LC' => 32, 'ST' => 25, 'SC' => 31, 'BY' => 28,
    ];
}

function promptscrub_iban_valid(string $candidate): bool
{
    $compact = strtoupper(preg_replace('/\s+/', '', $candidate) ?? '');
    if (preg_match('/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/', $compact) !== 1) {
        return false;
    }
    $country = substr($compact, 0, 2);
    $lengths = promptscrub_iban_lengths();
    if (!isset($lengths[$country]) || strlen($compact) !== $lengths[$country]) {
        return false;
    }
    $rearranged = substr($compact, 4) . substr($compact, 0, 4);
    $numeric = '';
    $letters = strlen($rearranged);
    for ($i = 0; $i < $letters; $i++) {
        $char = $rearranged[$i];
        if ($char >= 'A' && $char <= 'Z') {
            $numeric .= (string) (ord($char) - 55);
        } else {
            $numeric .= $char;
        }
    }
    $mod = 0;
    $digits = strlen($numeric);
    for ($i = 0; $i < $digits; $i++) {
        $mod = ($mod * 10 + (int) $numeric[$i]) % 97;
    }
    return $mod === 1;
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_ibans(string $text, array &$out): void
{
    $pattern = '/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,34}\b/';
    promptscrub_scan_pattern($text, $pattern, 'iban', 'IBAN', 70, $out, static function (array $match): ?array {
        $raw = $match[0][0];
        $start = $match[0][1];
        $compact = '';
        $end = $start;
        $length = strlen($raw);
        for ($i = 0; $i < $length; $i++) {
            $char = $raw[$i];
            if ($char === ' ') {
                $end = $start + $i + 1;
                continue;
            }
            $compact .= $char;
            $end = $start + $i + 1;
            if (promptscrub_iban_valid($compact)) {
                return [$start, $end];
            }
        }
        return null;
    });
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_env_secrets(string $text, array &$out): void
{
    $pattern = '/(?<![A-Za-z0-9])[\'"]?((?:[A-Za-z0-9]+[_\-.])*(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|PWD|TOKEN|CREDENTIAL|(?:API|ACCESS|PRIVATE|APP)[_-]?KEY|KEY))(?![A-Za-z0-9])/i';
    $found = preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
    if ($found === false) {
        throw new RuntimeException('Invalid env detector (PCRE ' . preg_last_error() . ')');
    }
    if ($found === 0) {
        return;
    }
    $length = strlen($text);
    foreach ($matches as $match) {
        $key = $match[1][0];
        $i = $match[1][1] + strlen($key);
        if ($i < $length && ($text[$i] === '"' || $text[$i] === "'")) {
            $i++;
        }
        while ($i < $length && ($text[$i] === ' ' || $text[$i] === "\t")) {
            $i++;
        }
        if ($i >= $length || ($text[$i] !== '=' && $text[$i] !== ':')) {
            continue;
        }
        $i++;
        while ($i < $length && ($text[$i] === ' ' || $text[$i] === "\t")) {
            $i++;
        }
        if ($i >= $length || $text[$i] === "\n" || $text[$i] === "\r") {
            continue;
        }
        $quote = null;
        if ($text[$i] === '"' || $text[$i] === "'") {
            $quote = $text[$i];
            $i++;
        }
        $valueStart = $i;
        if ($quote !== null) {
            while ($i < $length && $text[$i] !== $quote && $text[$i] !== "\n" && $text[$i] !== "\r") {
                $i++;
            }
            $valueEnd = $i;
        } else {
            while ($i < $length && !ctype_space($text[$i]) && $text[$i] !== '#') {
                $i++;
            }
            $valueEnd = $i;
            while ($valueEnd > $valueStart && str_contains(',;}', $text[$valueEnd - 1])) {
                $valueEnd--;
            }
        }
        $value = substr($text, $valueStart, $valueEnd - $valueStart);
        if (!promptscrub_env_value_is_secret($key, $value)) {
            continue;
        }
        promptscrub_push_span($out, $valueStart, $valueEnd, 'env_secret', 'Secret assigned to a sensitive name', 80);
    }
}

function promptscrub_key_is_strong(string $key): bool
{
    return preg_match('/secret|password|passwd|passphrase|token|credential|pwd|(?:api|access|private|app)[_-]?key/i', $key) === 1;
}

function promptscrub_env_value_is_secret(string $key, string $value): bool
{
    if (promptscrub_is_placeholder($value) || str_contains($value, '://')) {
        return false;
    }
    $length = strlen($value);
    if ($length < 8 || $length > 500) {
        return false;
    }
    if (!promptscrub_key_is_strong($key)) {
        if ($length < 20) {
            return false;
        }
        $hasLetter = preg_match('/[A-Za-z]/', $value) === 1;
        $mixed = preg_match('/\d/', $value) === 1 || preg_match('/[^A-Za-z0-9]/', $value) === 1;
        return $hasLetter && $mixed;
    }
    if ($length >= 16) {
        return true;
    }
    if (preg_match('/\d/', $value) === 1 || preg_match('/[^A-Za-z0-9]/', $value) === 1) {
        return true;
    }
    return $length >= 12;
}

function promptscrub_is_placeholder(string $value): bool
{
    $value = trim($value);
    if ($value === '') {
        return true;
    }
    $lower = strtolower($value);
    static $stop = null;
    if ($stop === null) {
        $words = [
            'password', 'secret', 'changeme', 'change_me', 'change-me', 'changeit', 'example',
            'placeholder', 'your_api_key', 'your-api-key', 'your_token', 'your-token',
            'your_password', 'yourpassword', 'your_key', 'yourkey', 'todo', 'fixme', 'required',
            'optional', 'string', 'boolean', 'integer', 'number', 'false', 'true', 'null',
            'none', 'nil', 'empty', 'nullable', 'default', 'disabled', 'enabled', 'yes', 'no',
            'off', 'on', 'undefined', 'test', 'testing', 'sample', 'dummy', 'fake', 'insert',
            'pass', 'apikey', 'token', 'secretkey', 'n/a', 'na', 'redacted', 'replace_me',
            'replace-me', 'set_me', 'set-me', 'not_set', 'not-set', 'insert_here', 'xxx',
            'xxxx', 'xxxxx', 'xxxxxx', 'xxxxxxxx', '********', '****', '*****', '******',
            '<secret>', '<token>', '<password>', '<key>', 'todo_change',
        ];
        $stop = array_fill_keys($words, true);
    }
    if (isset($stop[$lower])) {
        return true;
    }
    if (preg_match('/^(.)\1{3,}$/', $value) === 1) {
        return true;
    }
    if (preg_match('/^(your|my|some|example|sample|dummy|fake|test|insert|put|add)[-_]/i', $value) === 1) {
        return true;
    }
    if (preg_match('/^<.*>$/', $value) === 1) {
        return true;
    }
    if (preg_match('/^\$\{[^}]+\}$/', $value) === 1 || preg_match('/^\{\{[^}]+\}\}$/', $value) === 1) {
        return true;
    }
    if (preg_match('/^(xxx+|redacted|changeme.*|replace[-_]?me)$/i', $value) === 1) {
        return true;
    }
    return false;
}

/**
 * @param list<array{start:int,end:int,replacement:string,rule:string,label:string,priority:int}> $out
 */
function promptscrub_scan_emails(string $text, array &$out): void
{
    $pattern = '/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i';
    promptscrub_scan_pattern($text, $pattern, 'email', 'Email address', 90, $out, static function (array $match) use ($text): ?array {
        $email = $match[0][0];
        $start = $match[0][1];
        if (promptscrub_email_skipped($email) || promptscrub_email_in_url($text, $start) || promptscrub_email_is_git_remote($email, $text, $start)) {
            return null;
        }
        return [$start, $start + strlen($email)];
    });
}

function promptscrub_email_in_url(string $text, int $start): bool
{
    $begin = $start;
    $floor = max(0, $start - 200);
    for ($i = $start - 1; $i >= $floor; $i--) {
        if (ctype_space($text[$i])) {
            break;
        }
        $begin = $i;
    }
    $prefix = substr($text, $begin, $start - $begin);
    $scheme = strpos($prefix, '://');
    if ($scheme === false) {
        return false;
    }
    return !str_contains(substr($prefix, $scheme + 3), '/');
}

function promptscrub_email_is_git_remote(string $email, string $text, int $start): bool
{
    $after = $start + strlen($email);
    if ($after >= strlen($text) || $text[$after] !== ':') {
        return false;
    }
    $at = strrpos($email, '@');
    if ($at === false) {
        return false;
    }
    $local = strtolower(substr($email, 0, $at));
    $domain = strtolower(substr($email, $at + 1));
    if ($local === 'git') {
        return true;
    }
    return in_array($domain, ['github.com', 'gitlab.com', 'bitbucket.org'], true);
}

function promptscrub_email_skipped(string $email): bool
{
    $at = strrpos($email, '@');
    if ($at === false) {
        return true;
    }
    $domain = strtolower(substr($email, $at + 1));
    $exact = [
        'example.com' => true, 'example.org' => true, 'example.net' => true,
        'example.edu' => true, 'localhost' => true, 'test.com' => true,
        'email.com' => true, 'domain.com' => true, 'foo.com' => true, 'bar.com' => true,
    ];
    if (isset($exact[$domain])) {
        return true;
    }
    foreach (['.example', '.test', '.invalid', '.localhost'] as $suffix) {
        if (str_ends_with($domain, $suffix)) {
            return true;
        }
    }
    return false;
}

/**
 * @return list<string>
 */
function promptscrub_self_test(): array
{
    $failures = [];
    foreach (promptscrub_self_test_cases() as $name => $case) {
        $result = promptscrub_scrub($case['input'], $case['options'] ?? []);
        foreach ($case['absent'] ?? [] as $needle) {
            if ($needle !== '' && str_contains($result['redacted'], $needle)) {
                $failures[] = $name . ': secret still present';
            }
        }
        foreach ($case['present'] ?? [] as $needle) {
            if (!str_contains($result['redacted'], $needle)) {
                $failures[] = $name . ': expected marker ' . $needle;
            }
        }
        if (($case['unchanged'] ?? false) === true) {
            if ($result['redacted'] !== $case['input'] || $result['findings'] !== []) {
                $failures[] = $name . ': expected no change, got ' . $result['redacted'];
            }
        }
        if (isset($case['rules'])) {
            $got = array_column($result['findings'], 'rule');
            $expect = $case['rules'];
            sort($got);
            sort($expect);
            if ($got !== $expect) {
                $failures[] = $name . ': rules expected [' . implode(',', $expect) . '] got [' . implode(',', $got) . ']';
            }
        }
        if (isset($case['line'])) {
            $lines = array_column($result['findings'], 'line');
            if (!in_array($case['line'], $lines, true)) {
                $failures[] = $name . ': expected line ' . $case['line'];
            }
        }
        foreach ($result['findings'] as $finding) {
            $keys = array_keys($finding);
            sort($keys);
            if ($keys !== ['label', 'line', 'rule']) {
                $failures[] = $name . ': finding leaked extra fields';
            }
            $encoded = json_encode($finding, JSON_UNESCAPED_SLASHES);
            foreach ($case['absent'] ?? [] as $needle) {
                if ($needle !== '' && is_string($encoded) && str_contains($encoded, $needle)) {
                    $failures[] = $name . ': finding JSON contains the secret';
                }
            }
        }
    }

    $source = file_get_contents(__FILE__);
    if ($source === false) {
        $failures[] = 'could not read source for leak meta-check';
    } else {
        $forbidden = [
            '/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/',
            '/\bghp_[A-Za-z0-9]{36}\b/',
            '/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/',
            '/\bsk_live_[A-Za-z0-9]{10,}\b/',
        ];
        foreach ($forbidden as $pattern) {
            if (preg_match($pattern, $source) === 1) {
                $failures[] = 'source contains a committable secret pattern ' . $pattern;
            }
        }
    }

    return $failures;
}

/**
 * Samples are built at runtime so the file itself never contains a live-looking credential.
 *
 * @return array<string, array{input:string,options?:array<string,bool>,absent?:list<string>,present?:list<string>,unchanged?:bool,rules?:list<string>,line?:int}>
 */
function promptscrub_self_test_cases(): array
{
    $repeat = static fn (string $seed, int $times): string => str_repeat($seed, $times);
    $aws = 'AKIA' . $repeat('B', 16);
    $github = 'ghp_' . $repeat('A', 36);
    $fine = 'github_pat_' . $repeat('C', 22);
    $gitlab = 'glpat-' . $repeat('d', 24);
    $slack = 'xoxb-' . $repeat('1', 12);
    $slackHook = 'https://hooks.slack.com/services/T' . $repeat('A', 8) . '/B' . $repeat('B', 8) . '/' . $repeat('C', 24);
    $stripe = 'sk_test_' . $repeat('K', 16);
    $openai = 'sk-' . $repeat('P', 24);
    $anthropic = 'sk-ant-' . $repeat('P', 24);
    $xai = 'xai-' . $repeat('Z', 24);
    $groq = 'gsk_' . $repeat('Q', 28);
    $google = 'AIza' . $repeat('G', 35);
    $sendgrid = 'SG.' . $repeat('S', 22) . '.' . $repeat('T', 43);
    $npm = 'npm_' . $repeat('n', 36);
    $pypi = 'pypi-' . $repeat('p', 60);
    $shopify = 'shpat_' . $repeat('s', 32);
    $hf = 'hf_' . $repeat('h', 34);
    $discord = 'https://discord.com/api/webhooks/123456789012345678/' . $repeat('d', 30);
    $awsSecret = $repeat('w', 40);
    $jwt = promptscrub_b64url_encode('{"alg":"HS256","typ":"JWT"}')
        . '.' . promptscrub_b64url_encode('{"sub":"user"}')
        . '.' . promptscrub_b64url_encode('signature');
    $notJwt = promptscrub_b64url_encode('{"typ":"nope"}')
        . '.' . promptscrub_b64url_encode('{"sub":"user"}')
        . '.' . promptscrub_b64url_encode('signature');
    $pem = '-----BEGIN ' . 'RSA PRIVATE KEY-----' . "\n"
        . $repeat('A', 64) . "\n"
        . '-----END ' . 'RSA PRIVATE KEY-----';
    $basic = base64_encode('ada:s3cret-value');
    $iban = 'GB82 WEST 1234 5698 7654 32';
    $ibanCompact = 'GB82WEST12345698765432';

    $cases = [
        'aws key' => [
            'input' => "seen $aws in log\n",
            'absent' => [$aws],
            'present' => ['[REDACTED:aws_access_key_id]'],
            'rules' => ['aws_access_key_id'],
            'line' => 1,
        ],
        'github token' => [
            'input' => $github,
            'absent' => [$github],
            'present' => ['[REDACTED:github_token]'],
            'rules' => ['github_token'],
        ],
        'github fine grained' => [
            'input' => $fine,
            'absent' => [$fine],
            'rules' => ['github_token'],
        ],
        'gitlab' => ['input' => $gitlab, 'absent' => [$gitlab], 'rules' => ['gitlab_token']],
        'slack token' => ['input' => $slack, 'absent' => [$slack], 'rules' => ['slack_token']],
        'slack webhook' => ['input' => $slackHook, 'absent' => [$slackHook], 'rules' => ['slack_webhook']],
        'stripe' => ['input' => $stripe, 'absent' => [$stripe], 'rules' => ['stripe_secret_key']],
        'openai' => ['input' => $openai, 'absent' => [$openai], 'rules' => ['openai_key']],
        'anthropic wins over openai prefix' => [
            'input' => $anthropic,
            'absent' => [$anthropic],
            'rules' => ['anthropic_key'],
        ],
        'xai' => ['input' => $xai, 'absent' => [$xai], 'rules' => ['xai_key']],
        'groq' => ['input' => $groq, 'absent' => [$groq], 'rules' => ['groq_key']],
        'google' => ['input' => $google, 'absent' => [$google], 'rules' => ['google_api_key']],
        'sendgrid' => ['input' => $sendgrid, 'absent' => [$sendgrid], 'rules' => ['sendgrid_key']],
        'npm' => ['input' => $npm, 'absent' => [$npm], 'rules' => ['npm_token']],
        'pypi' => ['input' => $pypi, 'absent' => [$pypi], 'rules' => ['pypi_token']],
        'shopify' => ['input' => $shopify, 'absent' => [$shopify], 'rules' => ['shopify_token']],
        'huggingface' => ['input' => $hf, 'absent' => [$hf], 'rules' => ['huggingface_token']],
        'discord' => ['input' => $discord, 'absent' => [$discord], 'rules' => ['discord_webhook']],
        'aws secret only with the name' => [
            'input' => 'aws_secret_access_key=' . $awsSecret,
            'absent' => [$awsSecret],
            'rules' => ['aws_secret_access_key'],
        ],
        'random 40 chars are not an aws secret' => [
            'input' => 'blob ' . $awsSecret . " blob\n",
            'unchanged' => true,
        ],
        'jwt' => [
            'input' => "auth $jwt\n",
            'absent' => [$jwt],
            'rules' => ['jwt'],
        ],
        'three segments without alg are kept' => [
            'input' => $notJwt,
            'unchanged' => true,
        ],
        'private key' => [
            'input' => $pem,
            'absent' => ['RSA PRIVATE KEY-----'],
            'present' => ['[REDACTED:private_key]'],
            'rules' => ['private_key'],
        ],
        'bearer' => [
            'input' => 'Authorization: Bearer ' . $repeat('b', 24),
            'absent' => [$repeat('b', 24)],
            'present' => ['Bearer [REDACTED:bearer_token]'],
            'rules' => ['bearer_token'],
        ],
        'basic' => [
            'input' => 'Authorization: Basic ' . $basic,
            'absent' => [$basic],
            'rules' => ['basic_auth'],
        ],
        'url password keeps the host' => [
            'input' => 'postgres://app:s3cr3t-value@db.internal:5432/app',
            'absent' => ['s3cr3t-value'],
            'present' => ['postgres://app:[REDACTED:url_password]@db.internal:5432/app'],
            'rules' => ['url_password'],
        ],
        'url without password' => [
            'input' => 'postgres://app@db.internal:5432/app',
            'unchanged' => true,
        ],
        'git remote kept' => [
            'input' => 'origin git@github.com:Nguemoue/promptscrub.git',
            'unchanged' => true,
        ],
        'internal email' => [
            'input' => 'mail ada@corp.internal',
            'absent' => ['ada@corp.internal'],
            'rules' => ['email'],
        ],
        'placeholder password in url' => [
            'input' => 'mysql://root:changeme@localhost/db',
            'unchanged' => true,
        ],
        'redis empty user' => [
            'input' => 'redis://:s3cret!!@localhost:6379',
            'absent' => ['s3cret!!'],
            'present' => ['redis://:[REDACTED:url_password]@localhost:6379'],
        ],
        'card grouped' => [
            'input' => 'paid with 4242 4242 4242 4242 today',
            'absent' => ['4242 4242 4242 4242'],
            'rules' => ['payment_card'],
        ],
        'card failing luhn' => [
            'input' => 'paid with 4242 4242 4242 4243 today',
            'unchanged' => true,
        ],
        'bare digits without keyword stay' => [
            'input' => 'id 4242424242424242 ok',
            'unchanged' => true,
        ],
        'digits with keyword go' => [
            'input' => 'card 4242424242424242',
            'absent' => ['4242424242424242'],
            'rules' => ['payment_card'],
        ],
        'iban spaced' => [
            'input' => 'pay ' . $iban . ' thanks',
            'absent' => ['GB82'],
            'rules' => ['iban'],
        ],
        'iban compact' => [
            'input' => $ibanCompact,
            'absent' => [$ibanCompact],
            'rules' => ['iban'],
        ],
        'iban bad checksum' => [
            'input' => 'GB00WEST12345698765432',
            'unchanged' => true,
        ],
        'email' => [
            'input' => 'write ada@acme.io please',
            'absent' => ['ada@acme.io'],
            'rules' => ['email'],
        ],
        'example email kept' => [
            'input' => 'write ada@example.com please',
            'unchanged' => true,
        ],
        'reserved tld kept' => [
            'input' => 'write ada@company.test please',
            'unchanged' => true,
        ],
        'email can be disabled' => [
            'input' => 'write ada@acme.io please',
            'options' => ['email' => false],
            'unchanged' => true,
        ],
        'app key' => [
            'input' => 'APP_KEY=base64:dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU',
            'absent' => ['dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU'],
            'present' => ['APP_KEY=[REDACTED:env_secret]'],
            'rules' => ['env_secret'],
        ],
        'json password' => [
            'input' => '{"password":"correct-horse-battery"}',
            'absent' => ['correct-horse-battery'],
            'present' => ['"password":"[REDACTED:env_secret]"'],
        ],
        'php assignment' => [
            'input' => '$password = "hunter22xx";',
            'absent' => ['hunter22xx'],
            'present' => ['$password = "[REDACTED:env_secret]";'],
        ],
        'placeholder password kept' => [
            'input' => "DB_PASSWORD=changeme\nAPI_KEY=your_api_key_here\nTOKEN=xxxxxxxx\n",
            'unchanged' => true,
        ],
        'short and doc words kept' => [
            'input' => "API_KEY=required\nTOKEN=short\n",
            'unchanged' => true,
        ],
        'password with digit' => [
            'input' => 'MAIL_PASSWORD=password123',
            'absent' => ['password123'],
            'rules' => ['env_secret'],
        ],
        'bare key in prose kept' => [
            'input' => 'key: configuration',
            'unchanged' => true,
        ],
        'foreign key kept' => [
            'input' => 'foreign_key: user_id',
            'unchanged' => true,
        ],
        'keyboard kept' => [
            'input' => 'keyboard=mechanical-switch-type',
            'unchanged' => true,
        ],
        'uuid kept' => [
            'input' => 'id 550e8400-e29b-41d4-a716-446655440000',
            'unchanged' => true,
        ],
        'database url prefers password span' => [
            'input' => 'DATABASE_URL=postgres://app:s3cr3t-value@db.internal/app',
            'absent' => ['s3cr3t-value'],
            'present' => ['DATABASE_URL=postgres://app:[REDACTED:url_password]@db.internal/app'],
            'rules' => ['url_password'],
        ],
        'github token wins over env name' => [
            'input' => 'GITHUB_TOKEN=' . $github,
            'absent' => [$github],
            'present' => ['GITHUB_TOKEN=[REDACTED:github_token]'],
            'rules' => ['github_token'],
        ],
        'line numbers' => [
            'input' => "ok\n$aws\n",
            'line' => 2,
            'rules' => ['aws_access_key_id'],
            'absent' => [$aws],
        ],
        'two findings one line' => [
            'input' => "ada@acme.io $github",
            'absent' => ['ada@acme.io', $github],
            'rules' => ['email', 'github_token'],
        ],
        'empty' => [
            'input' => '',
            'unchanged' => true,
        ],
    ];

    return $cases;
}

function promptscrub_b64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function promptscrub_main(array $argv): int
{
    $options = [
        'email' => true,
        'iban' => true,
        'cards' => true,
        'json' => false,
        'check' => false,
        'output' => null,
        'stdin' => false,
        'help' => false,
        'selftest' => false,
        'rules' => false,
        'version' => false,
        'paths' => [],
    ];

    $args = array_slice($argv, 1);
    $count = count($args);
    for ($i = 0; $i < $count; $i++) {
        $arg = $args[$i];
        switch ($arg) {
            case '-h':
            case '--help':
                $options['help'] = true;
                break;
            case '--self-test':
                $options['selftest'] = true;
                break;
            case '--json':
                $options['json'] = true;
                break;
            case '--check':
                $options['check'] = true;
                break;
            case '--no-email':
                $options['email'] = false;
                break;
            case '--no-iban':
                $options['iban'] = false;
                break;
            case '--no-cards':
                $options['cards'] = false;
                break;
            case '--stdin':
                $options['stdin'] = true;
                break;
            case '--rules':
                $options['rules'] = true;
                break;
            case '--version':
                $options['version'] = true;
                break;
            case '-o':
            case '--output':
                $i++;
                if (!isset($args[$i])) {
                    fwrite(STDERR, "Valeur manquante pour $arg\n");
                    return 1;
                }
                $options['output'] = $args[$i];
                break;
            case '-':
                $options['stdin'] = true;
                break;
            default:
                if (str_starts_with($arg, '-')) {
                    fwrite(STDERR, "Option inconnue : $arg\n");
                    return 1;
                }
                $options['paths'][] = $arg;
        }
    }

    if ($options['help']) {
        fwrite(STDOUT, promptscrub_help());
        return 0;
    }
    if ($options['version']) {
        fwrite(STDOUT, PROMPTSCRUB_VERSION . "\n");
        return 0;
    }
    if ($options['rules']) {
        fwrite(STDOUT, promptscrub_rules_text());
        return 0;
    }
    if ($options['selftest']) {
        $failures = promptscrub_self_test();
        if ($failures === []) {
            fwrite(STDOUT, "PromptScrub self-test : OK\n");
            return 0;
        }
        fwrite(STDERR, "PromptScrub self-test : " . count($failures) . " échec(s)\n");
        foreach ($failures as $failure) {
            fwrite(STDERR, "  - $failure\n");
        }
        return 3;
    }

    $useStdin = $options['stdin'] || ($options['paths'] === [] && !stream_isatty(STDIN));
    if ($useStdin && $options['paths'] !== []) {
        fwrite(STDERR, "Choisis un fichier ou stdin, pas les deux.\n");
        return 1;
    }
    if (!$useStdin && $options['paths'] === []) {
        fwrite(STDOUT, promptscrub_help());
        return 0;
    }

    $inputs = [];
    if ($useStdin) {
        $data = stream_get_contents(STDIN);
        if ($data === false) {
            fwrite(STDERR, "Lecture de stdin impossible.\n");
            return 1;
        }
        $inputs[] = ['name' => '-', 'text' => $data];
    } else {
        foreach ($options['paths'] as $path) {
            if (!file_exists($path)) {
                fwrite(STDERR, "Introuvable : $path\n");
                return 1;
            }
            if (is_dir($path)) {
                foreach (promptscrub_collect_files($path) as $file) {
                    $text = promptscrub_read_file($file);
                    if ($text === null) {
                        continue;
                    }
                    $inputs[] = ['name' => $file, 'text' => $text];
                }
                continue;
            }
            $text = promptscrub_read_file($path);
            if ($text === null) {
                fwrite(STDERR, "Illisible : $path\n");
                return 1;
            }
            $inputs[] = ['name' => $path, 'text' => $text];
        }
    }

    $multiple = count($inputs) !== 1;
    if ($options['output'] !== null && ($multiple || $options['check'])) {
        fwrite(STDERR, "--output ne s'utilise qu'avec une seule entrée, sans --check.\n");
        return 1;
    }

    $scrubOptions = [
        'email' => $options['email'],
        'iban' => $options['iban'],
        'cards' => $options['cards'],
    ];
    $allFindings = [];
    $counts = [];
    $redactedSingle = null;
    foreach ($inputs as $input) {
        $result = promptscrub_scrub($input['text'], $scrubOptions);
        if (!$multiple) {
            $redactedSingle = $result['redacted'];
        }
        foreach ($result['findings'] as $finding) {
            $finding['file'] = $input['name'];
            $allFindings[] = $finding;
            $counts[$finding['rule']] = ($counts[$finding['rule']] ?? 0) + 1;
        }
    }
    if (count($allFindings) > 1000) {
        $allFindings = array_slice($allFindings, 0, 1000);
        $truncated = true;
    } else {
        $truncated = false;
    }

    $findingCount = array_sum($counts);
    if ($options['json']) {
        $payload = [
            'ok' => $findingCount === 0,
            'version' => PROMPTSCRUB_VERSION,
            'files_scanned' => count($inputs),
            'findings_count' => $findingCount,
            'counts' => $counts,
            'truncated' => $truncated,
            'findings' => $allFindings,
        ];
        if ($redactedSingle !== null) {
            $payload['redacted'] = $redactedSingle;
        }
        fwrite(STDOUT, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    } else {
        $showBody = $redactedSingle !== null && !$options['check'];
        if ($showBody) {
            $destination = STDOUT;
            if ($options['output'] !== null) {
                $opened = fopen($options['output'], 'wb');
                if ($opened === false) {
                    fwrite(STDERR, "Impossible d'écrire " . $options['output'] . "\n");
                    return 1;
                }
                $destination = $opened;
            }
            fwrite($destination, $redactedSingle);
            if ($options['output'] !== null) {
                fclose($destination);
            }
        }
        promptscrub_write_summary($findingCount, $allFindings, count($inputs), $truncated);
    }

    if ($options['check'] && $findingCount > 0) {
        return 2;
    }
    return 0;
}

/**
 * @param list<array{rule:string,label:string,line:int,file?:string}> $findings
 */
function promptscrub_write_summary(int $findingCount, array $findings, int $files, bool $truncated): void
{
    if ($findingCount === 0) {
        fwrite(STDERR, "PromptScrub : rien à masquer ($files fichier(s)).\n");
        return;
    }
    fwrite(STDERR, "PromptScrub : $findingCount élément(s) masqué(s) dans $files fichier(s).\n");
    $shown = 0;
    foreach ($findings as $finding) {
        if ($shown >= 100) {
            break;
        }
        $where = ($finding['file'] ?? '-') . ':' . $finding['line'];
        fwrite(STDERR, '  ' . $where . '  ' . $finding['rule'] . '  ' . $finding['label'] . "\n");
        $shown++;
    }
    $hidden = $findingCount - $shown;
    if ($hidden > 0 || $truncated) {
        fwrite(STDERR, "  … rapport tronqué\n");
    }
}

function promptscrub_read_file(string $path): ?string
{
    if (is_dir($path)) {
        return null;
    }
    $size = filesize($path);
    if ($size !== false && $size > 5_000_000) {
        fwrite(STDERR, "Ignoré (> 5 Mo) : $path\n");
        return null;
    }
    $text = file_get_contents($path);
    if ($text === false) {
        return null;
    }
    if (str_contains($text, "\0")) {
        return null;
    }
    return $text;
}

/**
 * @return list<string>
 */
function promptscrub_collect_files(string $directory): array
{
    $skip = array_fill_keys(['vendor', 'node_modules', '.git', '.idea', 'dist', 'build', 'storage'], true);
    $extensions = array_fill_keys([
        'php', 'env', 'log', 'json', 'yml', 'yaml', 'xml', 'ini', 'txt', 'md', 'js', 'ts',
        'vue', 'py', 'rb', 'go', 'java', 'sql', 'conf', 'cfg', 'toml', 'sh', 'example',
        'css', 'html', 'twig', 'blade', 'lock', 'xml', 'dist', 'neon', 'ini',
    ], true);
    $out = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $path = $file->getPathname();
        $parts = explode('/', str_replace('\\', '/', $path));
        $ignored = false;
        foreach ($parts as $part) {
            if (isset($skip[$part])) {
                $ignored = true;
                break;
            }
        }
        if ($ignored) {
            continue;
        }
        $base = $file->getFilename();
        if ($base === '.env' || str_starts_with($base, '.env')) {
            $out[] = $path;
            continue;
        }
        $ext = strtolower($file->getExtension());
        if (isset($extensions[$ext])) {
            $out[] = $path;
        }
    }
    sort($out);
    return $out;
}

function promptscrub_help(): string
{
    return <<<TXT
PromptScrub — masque secrets et données perso avant de coller un log.

Usage :
  php promptscrub.php [options] [fichier|dossier|-]

Options :
  -o, --output FICHIER   Écrit le texte masqué dans FICHIER (une seule entrée)
  --json                 Rapport JSON sur stdout
  --check                Code de sortie 2 si quelque chose a été masqué
  --no-email             Ne masque pas les adresses e-mail
  --no-iban              Ne masque pas les IBAN
  --no-cards             Ne masque pas les numéros de carte
  --stdin                Lit l'entrée standard
  --rules                Liste les détecteurs
  --self-test            Lance les tests intégrés
  --version              Affiche la version
  -h, --help             Affiche cette aide

Sans argument, dans un terminal : cette aide. Dans un pipe : lit stdin.
Le texte masqué va sur stdout, le résumé sur stderr.

Codes :
  0  rien à signaler, ou masquage affiché
  1  erreur d'usage ou de lecture
  2  trouvailles, avec --check
  3  échec du self-test

TXT;
}

function promptscrub_rules_text(): string
{
    $lines = ["Détecteurs PromptScrub " . PROMPTSCRUB_VERSION, ''];
    $seen = [];
    foreach (promptscrub_token_patterns() as [$rule, $label]) {
        if (isset($seen[$rule])) {
            continue;
        }
        $seen[$rule] = true;
        $lines[] = '  ' . $rule . ' — ' . $label;
    }
    $extra = [
        'aws_secret_access_key' => 'AWS secret access key (seulement à côté de son nom)',
        'private_key' => 'Bloc PEM private key',
        'jwt' => 'JWT dont l\'en-tête déclare un alg',
        'bearer_token' => 'Authorization Bearer',
        'basic_auth' => 'Authorization Basic (user:password)',
        'url_password' => 'Mot de passe dans une URL (le host est conservé)',
        'payment_card' => 'Carte (Luhn) groupée, ou chiffres près d\'un mot-clé',
        'iban' => 'IBAN avec pays, longueur et clé mod 97',
        'env_secret' => 'Valeur assignée à un nom sensible (APP_KEY, TOKEN, PASSWORD…)',
        'email' => 'Adresse e-mail (example.com, .test, .invalid ignorés)',
    ];
    foreach ($extra as $rule => $label) {
        $lines[] = '  ' . $rule . ' — ' . $label;
    }
    $lines[] = '';
    $lines[] = 'Les valeurs placeholder (changeme, your_api_key, xxxx, ${VAR}) sont ignorées.';
    $lines[] = 'Ce n\'est pas une garantie : relis le texte avant de le publier.';
    $lines[] = '';
    return implode("\n", $lines);
}

function promptscrub_sample(): string
{
    return <<<TXT
[2026-10-17] deploy failed
contact ada@acme.io
DATABASE_URL=postgres://app:s3cr3t-value@db.internal:5432/app
APP_KEY=base64:dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU
MAIL_PASSWORD=changeme
API_KEY=your_api_key_here
card=4242 4242 4242 4242
iban=GB82 WEST 1234 5698 7654 32
trace id 550e8400-e29b-41d4-a716-446655440000

TXT;
}

/**
 * @param array<string,mixed> $post
 * @return array{0:int,1:string}
 */
function promptscrub_handle_http(string $method, array $post): array
{
    $method = strtoupper($method);
    if ($method !== 'GET' && $method !== 'POST') {
        return [405, promptscrub_render_page('', '', [], 'Méthode non autorisée.')];
    }
    if ($method === 'GET') {
        return [200, promptscrub_render_page('', '', [], '')];
    }
    $action = isset($post['action']) && is_string($post['action']) ? $post['action'] : 'scrub';
    if ($action === 'sample') {
        $text = promptscrub_sample();
    } else {
        $text = isset($post['text']) && is_string($post['text']) ? $post['text'] : '';
    }
    if (strlen($text) > 1_000_000) {
        return [413, promptscrub_render_page('', '', [], 'Texte trop long (1 Mo maximum).')];
    }
    if (trim($text) === '') {
        return [422, promptscrub_render_page('', '', [], 'Colle d\'abord un texte.')];
    }
    $result = promptscrub_scrub($text);
    return [200, promptscrub_render_page($text, $result['redacted'], $result['findings'], '')];
}

/**
 * @param list<array{rule:string,label:string,line:int}> $findings
 */
function promptscrub_render_page(string $input, string $redacted, array $findings, string $error): string
{
    $h = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $findingHtml = '';
    if ($redacted !== '' || $findings !== []) {
        if ($findings === []) {
            $findingHtml = '<p class="ok">Aucun secret détecté. Le texte est inchangé.</p>';
        } else {
            $items = '';
            $shown = array_slice($findings, 0, 200);
            foreach ($shown as $finding) {
                $items .= '<li><span>L' . $finding['line'] . '</span> ' . $h($finding['label']) . '</li>';
            }
            $extra = count($findings) - count($shown);
            if ($extra > 0) {
                $items .= '<li>… et ' . $extra . ' de plus</li>';
            }
            $findingHtml = '<h2>' . count($findings) . ' élément(s) masqué(s)</h2><ul>' . $items . '</ul>';
        }
        $findingHtml .= '<h2>Texte masqué</h2><textarea id="out" readonly>' . $h($redacted) . '</textarea>';
    }
    $errorHtml = $error !== '' ? '<p class="err">' . $h($error) . '</p>' : '';

    return '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>PromptScrub</title>'
        . '<style>'
        . ':root{color-scheme:dark;--bg:#14140f;--ink:#efe7d6;--muted:#b3aa96;--line:#3a362c;--accent:#e2a83a;--ok:#b7d39a;--err:#e39b8f}'
        . '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 ui-sans-serif,Segoe UI,sans-serif}'
        . 'main{max-width:820px;margin:0 auto;padding:32px 20px 64px}'
        . 'h1{font-size:28px;margin:0 0 4px}p.lead{color:var(--muted);margin:0 0 20px}'
        . 'textarea{width:100%;min-height:220px;background:#0e0e0b;color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:12px;font:13px/1.45 ui-monospace,monospace;resize:vertical}'
        . 'form{display:grid;gap:12px}.row{display:flex;gap:8px;flex-wrap:wrap}'
        . 'button{background:var(--accent);color:#1a1408;border:0;border-radius:999px;padding:10px 16px;font-weight:650;cursor:pointer}'
        . 'button.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}'
        . 'h2{font-size:16px;margin:22px 0 8px}ul{list-style:none;padding:0;margin:0}li{padding:6px 0;border-bottom:1px solid var(--line)}'
        . 'li span{display:inline-block;min-width:3.2em;color:var(--accent);font-variant-numeric:tabular-nums}'
        . '.ok{color:var(--ok)}.err{color:var(--err)}footer{color:var(--muted);font-size:13px;margin-top:28px}'
        . '</style></head><body><main>'
        . '<h1>PromptScrub</h1>'
        . '<p class="lead">Masque tes secrets avant de coller un log dans ChatGPT, Slack ou GitHub. Rien n\'est enregistré.</p>'
        . $errorHtml
        . '<form method="post" action="">'
        . '<textarea id="in" name="text" placeholder="Colle un log, un .env, une stack trace…">' . $h($input) . '</textarea>'
        . '<div class="row"><button type="submit" name="action" value="scrub">Masquer</button>'
        . '<button class="ghost" type="submit" name="action" value="sample">Charger un exemple</button></div>'
        . '</form>'
        . $findingHtml
        . '<footer>Traitement en mémoire, sur cette machine. Ne publie pas ce formulaire sur Internet : le texte transiterait par le serveur. Heuristique, pas une garantie — relis avant d\'envoyer.</footer>'
        . '</main></body></html>';
}

function promptscrub_web(): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    [$status, $html] = promptscrub_handle_http($method, $_POST);
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
    echo $html;
}

if (PHP_SAPI === 'cli') {
    $script = $_SERVER['SCRIPT_FILENAME'] ?? '';
    if ($script !== '' && realpath($script) === realpath(__FILE__)) {
        exit(promptscrub_main($argv));
    }
    return;
}

$script = $_SERVER['SCRIPT_FILENAME'] ?? '';
if ($script !== '' && realpath($script) === realpath(__FILE__)) {
    promptscrub_web();
}
