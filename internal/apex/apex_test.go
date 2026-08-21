package apex

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"EXAMPLE.COM", "example.com", false},
		{"example.com.", "example.com", false},
		{"  example.com  ", "example.com", false},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", false},
		{"_bad.example.com", "", true},
		{"", "", true},
		{"foo.local", "", true},
		{"bar.test", "", true},
		{"x.home.arpa", "", true},
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Normalize(%q): want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Normalize(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateApex(t *testing.T) {
	if _, err := ValidateApex("www.example.com"); err == nil {
		t.Error("subdomain accepted as apex")
	}
	if _, err := ValidateApex("co.uk"); err == nil {
		t.Error("public suffix accepted as apex")
	}
	if got, err := ValidateApex("example.com"); err != nil || got != "example.com" {
		t.Errorf("ValidateApex(example.com) = %q, %v", got, err)
	}
}

func TestApexOf(t *testing.T) {
	if a, ok := ApexOf("a.b.example.co.uk"); !ok || a != "example.co.uk" {
		t.Errorf("ApexOf co.uk case = %q, %v", a, ok)
	}
	if a, ok := ApexOf("myapp.github.io"); !ok || a != "myapp.github.io" {
		t.Errorf("private suffix handling = %q, %v", a, ok)
	}
}
