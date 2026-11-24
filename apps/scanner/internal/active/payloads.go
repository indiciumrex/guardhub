package active

// The payload catalogue (ADR-0008 §5). Every byte an active module may send
// is here, with the reason it is harmless. payloads_test.go enforces the
// do-no-harm rules on this list: no data-changing or locking SQL, no delays,
// no self-executing script, no destinations other than GuardHub's own
// canary (.invalid, never resolvable) or OOB names, at most 256 bytes. A new
// payload needs a second reviewer in its PR.

// Where a payload goes.
const (
	InQuery  = "query"  // the value of one query-string parameter
	InOrigin = "origin" // the Origin request header
)

// Payload is one reviewed probe value.
type Payload struct {
	ID      string
	Module  string // the active check that may send it
	In      string // InQuery or InOrigin
	Value   string // exact bytes ({oob}: the collaborator's per-probe URL)
	Control string // a harmless value of the same shape: a difference it also causes is no finding
	Why     string // why it cannot harm the target
}

// CanaryHost never resolves (RFC 6761 .invalid): redirect and CORS probes
// name it, and nothing ever connects to it.
const CanaryHost = "gh-canary.invalid"

// OOBPlaceholder is the whole value of an OOB payload; it is replaced by the
// collaborator's unique URL for each probe (oob.go).
const OOBPlaceholder = "{oob}"

// Payloads is the catalogue.
var Payloads = []Payload{
	{
		ID: "xss.marker.tag", Module: "active_xss", In: InQuery,
		Value: `gh7x"'<ghx7 data-gh=1>`, Control: `gh7xplain`,
		Why: "an unknown, attribute-only tag: it shows whether < > \" ' come back unencoded; nothing executes",
	},
	{
		ID: "xss.marker.attr", Module: "active_xss", In: InQuery,
		Value: `gh7a" data-gh7a="1`, Control: `gh7aplain`,
		Why: "breaks out of a quoted attribute into an inert data- attribute; nothing executes",
	},
	{
		ID: "xss.marker.attr1", Module: "active_xss", In: InQuery,
		Value: `gh7b' data-gh7a='1`, Control: `gh7bplain`,
		Why: "the same inert data- attribute break-out for a single-quoted attribute; nothing executes",
	},
	{
		ID: "sqli.quote", Module: "active_sqli", In: InQuery,
		Value: `gh'`, Control: `gh''`,
		Why: "a single quote (error-based): reading only; the doubled quote is the same length and valid SQL",
	},
	{
		ID: "sqli.bool.true", Module: "active_sqli", In: InQuery,
		Value: `1' AND '7'='7`, Control: `1' AND '7'='8`,
		Why: "a read-only boolean comparison; true and false variants must answer differently",
	},
	{
		ID: "sqli.bool.num.true", Module: "active_sqli", In: InQuery,
		Value: `1 AND 7=7`, Control: `1 AND 7=8`,
		Why: "a read-only numeric boolean comparison",
	},
	{
		ID: "redirect.canary.abs", Module: "active_redirect", In: InQuery,
		Value: "https://" + CanaryHost + "/", Control: "/",
		Why: "names a host that never resolves; the Location header is read, never followed",
	},
	{
		ID: "redirect.canary.proto", Module: "active_redirect", In: InQuery,
		Value: "//" + CanaryHost + "/", Control: "/",
		Why: "protocol-relative variant of the canary; never followed",
	},
	{
		ID: "ssrf.oob.http", Module: "active_ssrf", In: InQuery,
		Value: OOBPlaceholder, Control: "",
		Why: "a unique name on GuardHub's own collaborator; only a fetch of it is recorded, nothing internal is named",
	},
	{
		ID: "cors.canary.origin", Module: "active_cors", In: InOrigin,
		Value: "https://" + CanaryHost, Control: "",
		Why: "an Origin header only; the answer's CORS headers are read",
	},
	{
		ID: "cors.null.origin", Module: "active_cors", In: InOrigin,
		Value: "null", Control: "",
		Why: "the null origin (sandboxed frames); headers only",
	},
}

// PayloadByID returns the catalogue entry with id.
func PayloadByID(id string) (Payload, bool) {
	for _, p := range Payloads {
		if p.ID == id {
			return p, true
		}
	}
	return Payload{}, false
}
