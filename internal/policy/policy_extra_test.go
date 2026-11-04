package policy

import (
	"testing"
)

func TestValidateExtraPortsTable(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		primary int
		allow   bool
		want    []int
		err     bool
	}{
		{"valid", "1195,1196", 1194, false, []int{1195, 1196}, false},
		{"reserved ssh", "22", 1194, false, nil, true},
		{"reserved mgmt", "7505", 1194, false, nil, true},
		{"reserved primary", "1194", 1194, false, nil, true},
		{"too many", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17", 1194, false, nil, true},
		{"web allowed", "80,443", 1194, true, []int{80, 443}, false},
		{"web blocked", "80", 1194, false, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.allow {
				t.Setenv("OVNODE_ALLOW_EXTRA_WEB_PORTS", "1")
			} else {
				t.Setenv("OVNODE_ALLOW_EXTRA_WEB_PORTS", "")
			}
			got, err := ValidateExtraPorts(tc.raw, tc.primary)
			if tc.err {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v want %v", got, tc.want)
				}
			}
		})
	}
}

func TestParseExtraPortsReservedOmitted(t *testing.T) {
	t.Setenv("OVNODE_ALLOW_EXTRA_WEB_PORTS", "")
	got := ParseExtraPorts("22,80,1195", 1194)
	if len(got) != 1 || got[0] != 1195 {
		t.Fatalf("got %v, want [1195]", got)
	}
}
