package redact

import (
	"bytes"
	"sort"
)

// matcher finds the leftmost, longest pattern occurrence with a Rabin-Karp
// rolling hash over a window as long as the shortest pattern. A bit filter
// rejects most windows before the candidate map is consulted.
//
// A dense Aho-Corasick automaton costs 2 KB per state and a state per pattern
// byte; secrets and their variants are long, so this stays at O(patterns).
type matcher struct {
	w     int
	pow   uint64 // hashBase^(w-1)
	bits  []uint64
	cands map[uint64][]int // window hash -> pattern indices, longest first
	pats  [][]byte
}

const (
	hashBase   = 0x100000001b3
	filterBits = 16
)

func filterIndex(h uint64) uint64 { return (h * 0x9e3779b97f4a7c15) >> (64 - filterBits) }

func windowHash(b []byte) uint64 {
	var h uint64
	for _, c := range b {
		h = h*hashBase + uint64(c)
	}
	return h
}

func newMatcher(pats [][]byte) matcher {
	if len(pats) == 0 {
		return matcher{}
	}
	w := len(pats[0])
	for _, p := range pats {
		w = min(w, len(p))
	}
	m := matcher{
		w:     w,
		pow:   1,
		bits:  make([]uint64, (1<<filterBits)/64),
		cands: map[uint64][]int{},
		pats:  pats,
	}
	for range w - 1 {
		m.pow *= hashBase
	}
	for i, p := range pats {
		h := windowHash(p[:w])
		m.cands[h] = append(m.cands[h], i)
		f := filterIndex(h)
		m.bits[f/64] |= 1 << (f % 64)
	}
	for _, idx := range m.cands {
		sort.SliceStable(idx, func(a, b int) bool { return len(pats[idx[a]]) > len(pats[idx[b]]) })
	}
	return m
}

// next returns the leftmost start in [from, limit) at which a pattern matches
// b completely, and the index of the longest such pattern; idx is -1 if none.
func (m *matcher) next(b []byte, from, limit int) (start, idx int) {
	if m.w == 0 || from >= limit || len(b)-from < m.w {
		return -1, -1
	}
	h := windowHash(b[from : from+m.w])
	for i := from; i < limit; i++ {
		if f := filterIndex(h); m.bits[f/64]&(1<<(f%64)) != 0 {
			for _, idx := range m.cands[h] {
				p := m.pats[idx]
				if len(b)-i >= len(p) && bytes.Equal(b[i:i+len(p)], p) {
					return i, idx
				}
			}
		}
		if i+m.w >= len(b) {
			break
		}
		h = (h-uint64(b[i])*m.pow)*hashBase + uint64(b[i+m.w])
	}
	return -1, -1
}
