package wire

import (
	"cmp"
	"slices"
)

// Draft limits.
const (
	MaxKVBytes         = 1<<16 - 1 // section 8.3: length of an odd-type value
	MaxReasonLen       = 1024      // section 8.5
	MaxNamespaceFields = 32        // section 8.7
	MaxFullNameLen     = 4096      // section 8.7
	MaxGoAwayURI       = 8192      // section 9.2
	MaxMessageLen      = 1<<16 - 1 // section 9: 16-bit Message Length
)

// KV is a Key-Value-Pair (section 8.3): an even Type carries Value, an odd
// Type carries Bytes.
type KV struct {
	Type  uint64
	Value uint64
	Bytes []byte
}

// AppendKVs appends kvs sorted by Type, delta encoded, with no length.
func AppendKVs(b []byte, kvs []KV) []byte {
	sorted := slices.Clone(kvs)
	slices.SortStableFunc(sorted, func(x, y KV) int { return cmp.Compare(x.Type, y.Type) })
	var prev uint64
	for _, kv := range sorted {
		b = AppendVarint(b, kv.Type-prev)
		prev = kv.Type
		if kv.Type%2 == 0 {
			b = AppendVarint(b, kv.Value)
			continue
		}
		b = AppendVarint(b, uint64(len(kv.Bytes)))
		b = append(b, kv.Bytes...)
	}
	return b
}

// KVsLen returns the encoded length of kvs.
func KVsLen(kvs []KV) int { return len(AppendKVs(nil, kvs)) }

// ParseKVs parses Key-Value-Pairs filling all of p. Bytes values are
// copied.
func ParseKVs(p []byte) ([]KV, error) {
	r := NewReader(p)
	var out []KV
	var prev uint64
	for r.Len() > 0 {
		d, err := r.Varint()
		if err != nil {
			return nil, err
		}
		if addOverflows(prev, d) {
			return nil, violation("key-value type overflows")
		}
		t := prev + d
		prev = t
		kv := KV{Type: t}
		if t%2 == 0 {
			if kv.Value, err = r.Varint(); err != nil {
				return nil, err
			}
		} else {
			v, err := r.LenBytes(MaxKVBytes, "key-value")
			if err != nil {
				return nil, err
			}
			kv.Bytes = slices.Clone(v)
		}
		out = append(out, kv)
	}
	return out, nil
}

// Location is a Group and Object pair (section 8.2).
type Location struct {
	Group, Object uint64
}

// Less reports whether l comes before m.
func (l Location) Less(m Location) bool {
	return l.Group < m.Group || (l.Group == m.Group && l.Object < m.Object)
}

func appendLocation(b []byte, l Location) []byte {
	return AppendVarint(AppendVarint(b, l.Group), l.Object)
}

func readLocation(r *Reader) (Location, error) {
	g, err := r.Varint()
	if err != nil {
		return Location{}, err
	}
	o, err := r.Varint()
	return Location{g, o}, err
}

// AppendNamespace appends a Track Namespace (section 8.7).
func AppendNamespace(b []byte, ns []string) []byte {
	b = AppendVarint(b, uint64(len(ns)))
	for _, f := range ns {
		b = AppendVarint(b, uint64(len(f)))
		b = append(b, f...)
	}
	return b
}

// ReadNamespace reads a Track Namespace and enforces the draft limits.
func ReadNamespace(r *Reader) ([]string, error) {
	n, err := r.Varint()
	if err != nil {
		return nil, err
	}
	if n > MaxNamespaceFields {
		return nil, violation("too many namespace fields")
	}
	ns := make([]string, 0, n)
	total := 0
	for range n {
		f, err := r.LenBytes(MaxFullNameLen, "namespace field")
		if err != nil {
			return nil, err
		}
		if len(f) == 0 {
			return nil, violation("empty namespace field")
		}
		total += len(f)
		if total > MaxFullNameLen {
			return nil, violation("namespace too long")
		}
		ns = append(ns, string(f))
	}
	return ns, nil
}

// NamespaceLen returns the sum of the field lengths.
func NamespaceLen(ns []string) int {
	n := 0
	for _, f := range ns {
		n += len(f)
	}
	return n
}

func appendName(b []byte, name string) []byte {
	b = AppendVarint(b, uint64(len(name)))
	return append(b, name...)
}

// readFullName reads a namespace and a track name within the draft limits.
func readFullName(r *Reader) ([]string, string, error) {
	ns, err := ReadNamespace(r)
	if err != nil {
		return nil, "", err
	}
	name, err := r.LenBytes(MaxFullNameLen, "track name")
	if err != nil {
		return nil, "", err
	}
	if NamespaceLen(ns)+len(name) > MaxFullNameLen {
		return nil, "", violation("full track name too long")
	}
	return ns, string(name), nil
}

func appendReason(b []byte, reason string) []byte {
	if len(reason) > MaxReasonLen {
		reason = reason[:MaxReasonLen]
	}
	b = AppendVarint(b, uint64(len(reason)))
	return append(b, reason...)
}

func readReason(r *Reader) (string, error) {
	p, err := r.LenBytes(MaxReasonLen, "reason phrase")
	return string(p), err
}
