package sudoku

// Read access to a table for codecs that change tables inside a stream,
// which Conn and PackedConn, bound to one table, do not.

// IsHint reports whether a wire byte is a hint in the table's layout, not padding.
func (t *Table) IsHint(b byte) bool {
	return t.layout.isHint(b)
}

// DecodeHints returns the byte whose puzzle is the four hint wire bytes, in
// any order. Padding bytes and hints that are no puzzle of the table give false.
func (t *Table) DecodeHints(h [4]byte) (byte, bool) {
	l := t.layout
	a, b, c, d := l.hintIdx[h[0]], l.hintIdx[h[1]], l.hintIdx[h[2]], l.hintIdx[h[3]]
	if (a|b|c|d)&notHint != 0 {
		return 0, false
	}
	return t.decodeHints(a, b, c, d)
}

// PackedGroup returns the six bits a wire byte carries in the packed encoding, false for padding.
func (t *Table) PackedGroup(b byte) (byte, bool) {
	group := t.layout.decodeGroup[b]
	return group, group < 64
}

// PadMarker returns the padding byte that ends an incomplete packed group.
func (t *Table) PadMarker() byte {
	return t.layout.padMarker
}
