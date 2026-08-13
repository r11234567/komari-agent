package cmd

import "testing"

func TestAutoDiscoveryServerName(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		hostname   string
		want       string
		wantError  bool
	}{
		{name: "configured name wins", configured: "  edge-de  ", hostname: "host", want: "edge-de"},
		{name: "hostname fallback", hostname: "  host-01  ", want: "host-01"},
		{name: "both empty", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := autoDiscoveryServerName(test.configured, test.hostname)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("name = %q, want %q", got, test.want)
			}
		})
	}
}
