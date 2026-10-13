package discovery

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSampleRecordsCoverEveryType(t *testing.T) {
	seen := map[string]int{}
	for _, r := range SampleRecords() {
		seen[r.Type]++
	}
	for _, want := range RecordTypes {
		if seen[want] != 1 {
			t.Fatalf("record type %s appears %d times in SampleRecords; want exactly 1", want, seen[want])
		}
	}
	if len(seen) != len(RecordTypes) {
		t.Fatalf("SampleRecords emits %d distinct types; RecordTypes declares %d", len(seen), len(RecordTypes))
	}
}

// Nil slices and maps marshal as null, which the control plane's schema rejects for fields the
// contract declares as arrays or objects. Normalization must leave none behind.
func TestNormalizedRecordsContainNoNullCollections(t *testing.T) {
	records := SampleRecords()
	NormalizeRecords(records)
	raw, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(":null")) || bytes.Contains(raw, []byte(": null")) {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, raw, "", "  ")
		t.Fatalf("normalized records still contain a null field:\n%s", pretty.String())
	}
}

// The contract flattens every payload except `http` and `technology`.
func TestFlatPayloadsAreMergedOntoTheRecord(t *testing.T) {
	for _, r := range SampleRecords() {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal %s: %v", r.Type, err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("unmarshal %s: %v", r.Type, err)
		}
		for _, container := range []string{"artifact", "sourceMap", "apiSpec", "endpoint", "security", "secret", "secretScan"} {
			if _, found := obj[container]; found {
				t.Errorf("%s: payload is still nested under %q; the contract is flat", r.Type, container)
			}
		}
		switch r.Type {
		case TypeHTTPObservation:
			if _, found := obj["http"]; !found {
				t.Errorf("%s: expected a nested `http` object", r.Type)
			}
		case TypeTechnology:
			if _, found := obj["technology"]; !found {
				t.Errorf("%s: expected a nested `technology` object", r.Type)
			}
		}
	}
}
