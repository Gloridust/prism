package prism

import (
	"math/rand"
)

// Profile defines a traffic-shaping profile that makes Prism's frame-size
// distribution mimic a specific application pattern. Each profile specifies
// bucket boundaries (like "pad" mode) PLUS a probabilistic model that
// occasionally injects cover frames of characteristic sizes.
type Profile struct {
	Name    string
	Buckets []int    // length-shaping buckets (ascending); nil = no length shaping
	Cover   []Cover  // cover traffic injections between real frames
}

// Cover describes a probabilistic cover-traffic injection: with probability P
// (0.0–1.0), inject a PAD frame of Size bytes after a real DATA frame.
type Cover struct {
	Size int
	P    float64
}

// Profiles is the registry of built-in traffic profiles.
var Profiles = map[string]*Profile{
	"none": {Name: "none"},
	"pad":  {Name: "pad", Buckets: shapeBuckets},

	// "web" mimics a typical HTTPS browsing session: small request bursts
	// (64–576 bytes) interspersed with medium HTML/CSS/JS responses (1280–4096)
	// and occasional large resource loads. Cover traffic injects small
	// "keep-alive" frames at 15% probability to simulate browser polling.
	"web": {
		Name:    "web",
		Buckets: []int{64, 128, 256, 576, 1280, 4096, 16000},
		Cover: []Cover{
			{Size: 64, P: 0.15},
			{Size: 128, P: 0.05},
		},
	},

	// "video" mimics a video streaming session: mostly large fixed-size chunks
	// (the video segments) with periodic small control messages (manifest
	// updates, heartbeats). Buckets are biased toward large sizes; cover
	// traffic injects periodic small frames to simulate ABR control.
	"video": {
		Name:    "video",
		Buckets: []int{128, 576, 4096, 8192, 16000},
		Cover: []Cover{
			{Size: 128, P: 0.10},
			{Size: 576, P: 0.03},
		},
	},

	// "download" mimics a large file download: almost all frames are max-size
	// with rare small ACK-like frames. Minimal cover traffic since downloads
	// are characteristically bursty with large frames.
	"download": {
		Name:    "download",
		Buckets: []int{64, 576, 16000},
		Cover: []Cover{
			{Size: 64, P: 0.08},
		},
	},
}

// LookupProfile returns the named profile or nil.
func LookupProfile(name string) *Profile {
	return Profiles[name]
}

// PadLen returns how many pad bytes to add to a frame of plaintext length n.
func (p *Profile) PadLen(n int) int {
	if p == nil {
		return 0
	}
	for _, b := range p.Buckets {
		if n <= b {
			return b - n
		}
	}
	return 0
}

// ShouldCover returns a cover frame size to inject, or 0 if none. Called after
// each real DATA frame write to decide whether to inject a cover PAD.
func (p *Profile) ShouldCover() int {
	if p == nil {
		return 0
	}
	for _, c := range p.Cover {
		if rand.Float64() < c.P {
			return c.Size
		}
	}
	return 0
}
