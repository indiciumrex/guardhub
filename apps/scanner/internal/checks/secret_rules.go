package checks

// Secret rules for repo_secrets (ADR-0006 §9, docs/checks/repo_secrets.md).
// Each rule is provider-specific: a fixed prefix or structure that only that
// provider's credentials have, so a match is a credential, not a guess. The
// value must also pass the placeholder filter (placeholders.go). Publishable
// or short-lived tokens are deliberately absent (Google browser API keys,
// Stripe publishable keys, GitHub installation tokens).

import (
	"net"
	"regexp"
	"strings"
)

type secretRule struct {
	id         string // stable rule id (evidence, fingerprint)
	secretType string // finding param: what the user is told it is
	key        string // finding key: hardcoded_secret | test_mode_secret
	re         *regexp.Regexp
	group      int      // capture group holding the secret value
	keywords   []string // cheap prefilter: at least one must occur in the file
	// minEntropy for the value's random part (bits per char); 0 = rule's
	// structure is strict enough on its own.
	minEntropy float64
	// accept, when set, gets the full submatch and decides (e.g. database
	// URLs: not a local development host).
	accept func(m []string) bool
}

var secretRules = []secretRule{
	{
		id: "aws_secret_access_key", secretType: "AWS secret access key", key: "hardcoded_secret",
		re:       regexp.MustCompile(`(?i)aws[a-z0-9_.\-]{0,20}?(?:secret|sk)[a-z0-9_.\-]{0,20}?["']?\s*(?:=|:|:=|=>)\s*["']?([A-Za-z0-9/+]{40})(?:["'\s,;]|$)`),
		group:    1,
		keywords: []string{"aws", "AWS"}, minEntropy: 4.0,
	},
	{
		id: "github_pat", secretType: "GitHub personal access token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b`), group: 1,
		keywords: []string{"ghp_", "github_pat_"}, minEntropy: 3.5,
	},
	{
		id: "github_oauth", secretType: "GitHub OAuth or refresh token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b((?:gho|ghr)_[A-Za-z0-9]{36})\b`), group: 1,
		keywords: []string{"gho_", "ghr_"}, minEntropy: 3.5,
	},
	{
		id: "gitlab_pat", secretType: "GitLab personal access token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,})\b`), group: 1,
		keywords: []string{"glpat-"}, minEntropy: 3.5,
	},
	{
		id: "slack_token", secretType: "Slack token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(xox[baprs]-[0-9]{8,13}-[0-9A-Za-z-]{10,})\b`), group: 1,
		keywords: []string{"xox"}, minEntropy: 3.0,
	},
	{
		id: "slack_webhook", secretType: "Slack incoming webhook URL", key: "hardcoded_secret",
		re: regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})`), group: 1,
		keywords: []string{"hooks.slack.com"},
	},
	{
		id: "stripe_live_secret", secretType: "Stripe live secret key", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b`), group: 1,
		keywords: []string{"_live_"}, minEntropy: 3.5,
	},
	{
		id: "stripe_test_secret", secretType: "Stripe test-mode secret key", key: "test_mode_secret",
		re: regexp.MustCompile(`\b((?:sk|rk)_test_[A-Za-z0-9]{24,99})\b`), group: 1,
		keywords: []string{"_test_"}, minEntropy: 3.5,
	},
	{
		id: "private_key", secretType: "Private key", key: "hardcoded_secret",
		re:       regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----(?:\\n|\\r\\n|[\r\n]|\s)+((?:[A-Za-z0-9+/=]{16,}(?:\\n|\\r\\n|[\r\n]|\s)*){3,}?)(?:\\n|\\r\\n|[\r\n]|\s)*-----END `),
		group:    2,
		keywords: []string{"PRIVATE KEY"}, minEntropy: 4.0,
	},
	{
		id: "database_url", secretType: "Database connection string with password", key: "hardcoded_secret",
		re:       regexp.MustCompile(`\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://([^\s:/@'"` + "`" + `]{1,64}):([^\s@'"` + "`" + `/]{6,128})@([A-Za-z0-9.\-]{1,253})(?::\d{2,5})?)`),
		group:    3,
		keywords: []string{"://"}, minEntropy: 2.5,
		accept: func(m []string) bool { return remoteHost(m[4]) },
	},
	{
		id: "npm_token", secretType: "npm access token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), group: 1,
		keywords: []string{"npm_"}, minEntropy: 3.5,
	},
	{
		id: "pypi_token", secretType: "PyPI API token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})`), group: 1,
		keywords: []string{"pypi-AgEIcHlwaS5vcmc"}, minEntropy: 3.5,
	},
	{
		id: "sendgrid_key", secretType: "SendGrid API key", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`), group: 1,
		keywords: []string{"SG."}, minEntropy: 3.5,
	},
	{
		id: "openai_key", secretType: "OpenAI API key", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b`), group: 1,
		keywords: []string{"T3BlbkFJ"}, minEntropy: 3.5,
	},
	{
		id: "anthropic_key", secretType: "Anthropic API key", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})`), group: 1,
		keywords: []string{"sk-ant-"}, minEntropy: 3.5,
	},
	{
		id: "telegram_bot_token", secretType: "Telegram bot token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b([0-9]{8,10}:AA[0-9A-Za-z_\-]{33})\b`), group: 1,
		keywords: []string{":AA"}, minEntropy: 3.5,
	},
	{
		id: "shopify_token", secretType: "Shopify access token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b`), group: 1,
		keywords: []string{"shpat_", "shpca_", "shppa_", "shpss_"}, minEntropy: 3.0,
	},
	{
		id: "azure_storage_key", secretType: "Azure storage account key", key: "hardcoded_secret",
		re: regexp.MustCompile(`AccountKey=([A-Za-z0-9+/]{86}==)`), group: 1,
		keywords: []string{"AccountKey="}, minEntropy: 4.0,
	},
	{
		id: "digitalocean_token", secretType: "DigitalOcean access token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(do[po]_v1_[a-f0-9]{64})\b`), group: 1,
		keywords: []string{"dop_v1_", "doo_v1_"}, minEntropy: 3.0,
	},
	{
		id: "huggingface_token", secretType: "Hugging Face access token", key: "hardcoded_secret",
		re: regexp.MustCompile(`\b(hf_[A-Za-z]{34})\b`), group: 1,
		keywords: []string{"hf_"}, minEntropy: 3.5,
	},
}

// genericSecretRe: an assignment to a secret-sounding name of a quoted
// value. Reported as generic_secret (medium) only after the entropy and
// placeholder filters; never when a provider rule matched the same line.
var genericSecretRe = regexp.MustCompile(`(?i)\b([a-z0-9_.\-]{0,40}(?:secret|passw(?:or)?d|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key|client[_\-]?secret|signing[_\-]?key)[a-z0-9_\-]{0,20})["']?\s*(?:=|:|:=|=>)\s*["']([^"'\s]{16,200})["']`)

// genericNameExcluded: names that sound secret but hold public or
// non-secret values (identifiers, paths, URLs, public keys, hashes).
var genericNameExcluded = regexp.MustCompile(`(?i)(_id|_ids|id$|_url|url$|_uri|_path|path$|_file|file$|_name|name$|_type|type$|_hash|hash$|_endpoint|_header|_field|_param|_length|_len|_version|_env|_prefix|_suffix|_pattern|_regex|_label|_placeholder|_hint|public|publishable|_kms|_arn|_ref|_sha1|_sha256|_sha512|_md5|_digest|_checksum|_salt|_policy|_rules|_strength|_min|_max)$`)

// remoteHost: database URLs to loopback, single-label (compose service)
// or reserved example hosts are local development settings, not leaks.
func remoteHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]."))
	if h == "" || h == "localhost" || !strings.Contains(h, ".") {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
	}
	for _, suffix := range []string{".local", ".localhost", ".internal", ".test", ".example", ".invalid", "example.com", "example.org", "example.net", ".lan", ".home.arpa"} {
		if strings.HasSuffix(h, suffix) {
			return false
		}
	}
	return true
}
