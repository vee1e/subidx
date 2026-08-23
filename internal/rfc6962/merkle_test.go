package rfc6962

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// rootOf and pathOf are a reference RFC 6962 §2 Merkle tree built
// recursively, deliberately independent of the iterative verifier in
// merkle.go so the two must agree.
func rootOf(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		h := sha256.Sum256(nil)
		return h[:]
	}
	if len(leaves) == 1 {
		return LeafHash(leaves[0])
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	return nodeHash(rootOf(leaves[:k]), rootOf(leaves[k:]))
}

func pathOf(leaves [][]byte, idx int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	if idx < k {
		return append(pathOf(leaves[:k], idx), rootOf(leaves[k:]))
	}
	return append(pathOf(leaves[k:], idx-k), rootOf(leaves[:k]))
}

func randomLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		b := make([]byte, 40)
		rand.Read(b)
		leaves[i] = b
	}
	return leaves
}

func TestVerifyInclusionAgainstReferenceTree(t *testing.T) {
	// 1..33 crosses every power-of-two boundary up to 32.
	for n := 1; n <= 33; n++ {
		leaves := randomLeaves(n)
		root := rootOf(leaves)
		for i := 0; i < n; i++ {
			lh := LeafHash(leaves[i])
			if err := VerifyInclusion(lh, int64(i), int64(n), pathOf(leaves, i), root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
		}
	}
}

func TestVerifyInclusionRejectsTampering(t *testing.T) {
	n := 8
	leaves := randomLeaves(n)
	root := rootOf(leaves)
	idx := 3
	lh := LeafHash(leaves[idx])
	path := pathOf(leaves, idx)
	if err := VerifyInclusion(lh, int64(idx), int64(n), path, root); err != nil {
		t.Fatal(err)
	}

	flip := func(b []byte) []byte {
		out := bytes.Clone(b)
		out[0] ^= 1
		return out
	}

	if err := VerifyInclusion(lh, int64(idx), int64(n), path, flip(root)); err == nil {
		t.Fatal("wrong root accepted")
	}

	tamperedPath := make([][]byte, len(path))
	copy(tamperedPath, path)
	tamperedPath[1] = flip(tamperedPath[1])
	if err := VerifyInclusion(lh, int64(idx), int64(n), tamperedPath, root); err == nil {
		t.Fatal("tampered audit path accepted")
	}

	if err := VerifyInclusion(lh, int64(idx+1), int64(n), path, root); err == nil {
		t.Fatal("wrong leaf index accepted")
	}

	if err := VerifyInclusion(lh, int64(idx), int64(n), path[:1], root); err == nil {
		t.Fatal("truncated audit path accepted")
	}

	if err := VerifyInclusion(lh, int64(n), int64(n), path, root); err == nil {
		t.Fatal("out-of-range leaf index accepted")
	}

	if err := VerifyInclusion(lh, int64(idx), 0, path, root); err == nil {
		t.Fatal("zero tree size accepted")
	}

	// A leaf that is not in the tree, even with the honest path.
	foreign := LeafHash([]byte("not in this tree"))
	if err := VerifyInclusion(foreign, int64(idx), int64(n), path, root); err == nil {
		t.Fatal("foreign leaf hash accepted")
	}
}
