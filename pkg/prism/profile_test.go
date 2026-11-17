package prism

import "testing"

func TestProfileLookup(t *testing.T) {
	for _, name := range []string{"none", "pad", "web", "video", "download"} {
		if LookupProfile(name) == nil {
			t.Errorf("LookupProfile(%q) = nil, want non-nil", name)
		}
	}
	if LookupProfile("nonexistent") != nil {
		t.Error("LookupProfile(nonexistent) should be nil")
	}
}

func TestProfilePadLen(t *testing.T) {
	web := LookupProfile("web")
	if web == nil {
		t.Fatal("web profile not found")
	}
	if p := web.PadLen(50); p != 64-50 {
		t.Errorf("PadLen(50) = %d, want %d", p, 64-50)
	}
	if p := web.PadLen(64); p != 0 {
		t.Errorf("PadLen(64) = %d, want 0", p)
	}
	if p := web.PadLen(20000); p != 0 {
		t.Errorf("PadLen(20000) = %d, want 0 (exceeds max bucket)", p)
	}

	var nilProfile *Profile
	if p := nilProfile.PadLen(100); p != 0 {
		t.Errorf("nil.PadLen(100) = %d, want 0", p)
	}
}

func TestProfileShouldCover(t *testing.T) {
	web := LookupProfile("web")
	hits := 0
	for i := 0; i < 10000; i++ {
		if web.ShouldCover() > 0 {
			hits++
		}
	}
	if hits == 0 {
		t.Error("web profile never generated cover traffic in 10000 trials")
	}
	if hits == 10000 {
		t.Error("web profile always generated cover traffic (unexpected)")
	}

	none := LookupProfile("none")
	for i := 0; i < 1000; i++ {
		if none.ShouldCover() > 0 {
			t.Fatal("none profile should never generate cover traffic")
		}
	}

	var nilProfile *Profile
	if nilProfile.ShouldCover() != 0 {
		t.Error("nil profile should return 0")
	}
}
