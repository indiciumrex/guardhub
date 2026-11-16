package queue

import (
	"errors"
	"testing"
	"time"
)

func TestParseJobValid(t *testing.T) {
	j, err := ParseJob(`{"v":1,"kind":"scan","job_id":"9b2f-1","scan_id":"5a7c-2","target":"https://Example.com/","checks":["exposed_env","security_headers"],"deadline_seconds":120,"future_field":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if j.Target != "https://example.com" || len(j.Checks) != 2 || j.Deadline() != 120*time.Second {
		t.Fatalf("%+v", j)
	}
	v, err := ParseJob(`{"v":1,"kind":"verify","job_id":"abc","target":"http://example.com:8080","token":"ghv_abc123","reply_key":"gh:verify-reply:abc"}`)
	if err != nil || v.Token != "ghv_abc123" || v.ReplyKey != "gh:verify-reply:abc" {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestDeadlineClamp(t *testing.T) {
	cases := map[int]time.Duration{0: 180 * time.Second, -5: 180 * time.Second, 30: 30 * time.Second, 300: 300 * time.Second, 9999: 300 * time.Second}
	for in, want := range cases {
		if got := (Job{DeadlineSeconds: in}).Deadline(); got != want {
			t.Errorf("deadline %d: got %v want %v", in, got, want)
		}
	}
}

func TestParseJobMalformed(t *testing.T) {
	cases := map[string]string{
		"not json":         `{{{`,
		"empty":            ``,
		"wrong version":    `{"v":2,"kind":"scan","job_id":"a","scan_id":"b","target":"https://x.test"}`,
		"unknown kind":     `{"v":1,"kind":"exploit","job_id":"a","target":"https://x.test"}`,
		"missing job_id":   `{"v":1,"kind":"scan","scan_id":"b","target":"https://x.test"}`,
		"bad scan_id":      `{"v":1,"kind":"scan","job_id":"a","scan_id":"b:evil","target":"https://x.test"}`,
		"target with path": `{"v":1,"kind":"scan","job_id":"a","scan_id":"b","target":"https://x.test/admin"}`,
		"target scheme":    `{"v":1,"kind":"scan","job_id":"a","scan_id":"b","target":"file:///etc/passwd"}`,
		"target creds":     `{"v":1,"kind":"scan","job_id":"a","scan_id":"b","target":"https://u:p@x.test"}`,
		"bad reply_key":    `{"v":1,"kind":"verify","job_id":"a","target":"https://x.test","token":"t","reply_key":"gh:jobs"}`,
		"missing token":    `{"v":1,"kind":"verify","job_id":"a","target":"https://x.test","reply_key":"gh:verify-reply:a"}`,
		"token with space": `{"v":1,"kind":"verify","job_id":"a","target":"https://x.test","token":"a b","reply_key":"gh:verify-reply:a"}`,
	}
	for name, payload := range cases {
		if _, err := ParseJob(payload); !errors.Is(err, ErrMalformedJob) {
			t.Errorf("%s: expected ErrMalformedJob, got %v", name, err)
		}
	}
	// Partial decode is kept so the API can be told.
	j, err := ParseJob(`{"v":1,"kind":"scan","job_id":"a","scan_id":"s1","target":"nope"}`)
	if err == nil || j.ScanID != "s1" {
		t.Fatalf("partial job not returned: %+v %v", j, err)
	}
}
