package rfc6962

import (
	"crypto/sha256"
	"fmt"
)

// LeafHash returns the RFC 6962 §2 hash of a single leaf:
// SHA-256(0x00 || leaf). Entries are committed to a log's signed root
// hash under exactly this identity.
func LeafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	return h.Sum(nil)
}

// nodeHash returns SHA-256(0x01 || l || r), the hash of an interior node.
func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// VerifyInclusion checks an audit path (the body of get-proof-by-hash)
// against a signed root: that leafHash sits at leafIndex in a tree of
// treeSize leaves and hashes up to root, per RFC 6962 §2.1.2. The
// verification is computed locally, so neither the log nor a man in the
// middle can forge it for data the root does not commit to.
func VerifyInclusion(leafHash []byte, leafIndex, treeSize int64, auditPath [][]byte, root []byte) error {
	if len(leafHash) != sha256.Size {
		return fmt.Errorf("leaf hash has %d bytes; want 32", len(leafHash))
	}
	if len(root) != sha256.Size {
		return fmt.Errorf("root hash has %d bytes; want 32", len(root))
	}
	if treeSize <= 0 {
		return fmt.Errorf("tree size %d must be positive", treeSize)
	}
	if leafIndex < 0 || leafIndex >= treeSize {
		return fmt.Errorf("leaf index %d out of range for tree size %d", leafIndex, treeSize)
	}
	fn := leafIndex
	sn := treeSize - 1
	r := leafHash
	for _, p := range auditPath {
		if len(p) != sha256.Size {
			return fmt.Errorf("audit path node has %d bytes; want 32", len(p))
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn != 0 && fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("audit path too short for tree size %d", treeSize)
	}
	if string(r) != string(root) {
		return fmt.Errorf("computed root does not match signed root")
	}
	return nil
}
