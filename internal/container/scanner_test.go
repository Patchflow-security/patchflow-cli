package container

import "testing"

func TestValidateImageRef(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		wantErr bool
	}{
		{name: "simple", image: "nginx:1.25"},
		{name: "registry", image: "ghcr.io/patchflow-security/cli:v0.1.0"},
		{name: "empty", image: "", wantErr: true},
		{name: "flag injection", image: "--help", wantErr: true},
		{name: "newline", image: "nginx:latest\n--debug", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateImageRef(tc.image)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
