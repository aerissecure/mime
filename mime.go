// Package mime provides mime type recognition using file magic numbers.
// It is currently geared primarily toward archive applications

package mime

import (
	"bytes"
)

// The algorithm uses at most sniffLen bytes to make its decision.
const sniffLen = 512

type MIME int

const (
	Unknown MIME = iota
	Zip
	Rar
	Gzip
	Bzip
	Bzip2
	Tar
	PDF
	Xz
	Lz4
	// Sz
	OctetStream
)

func (m MIME) String() string {
	switch m {
	case Zip:
		return "application/zip"
	case Rar:
		return "application/x-rar"
	case Gzip:
		return "application/x-gzip"
	case Bzip:
		return "application/x-bzip"
	case Bzip2:
		return "application/x-bzip2"
	case Tar:
		return "application/x-tar"
	case PDF:
		return "application/pdf"
	case Xz:
		return "application/x-xz"
	case Lz4:
		return "application/x-lz4"
	// case Sz:
	// 	return "application/x-snappy-framed"
	case OctetStream:
		return "application/octet-stream"
	}
	return ""
}

// Detect implements the algorithm described
// at https://mimesniff.spec.whatwg.org/ to determine the
// MIME type of the given data. It considers at most the
// first 512 bytes of data. DetectContentType always returns
// a valid MIME type: if it cannot determine a more specific one, it
// returns "application/octet-stream".
func Detect(data []byte) MIME {
	if len(data) > sniffLen {
		data = data[:sniffLen]
	}

	for _, sig := range sniffSignatures {
		if mt := sig.match(data); mt != Unknown {
			return mt
		}
	}

	return OctetStream // fallback
}

type sniffSig interface {
	// match returns the MIME type of the data, or "" if unknown.
	match(data []byte) MIME
}

// Data matching the table in section 6.
var sniffSignatures = []sniffSig{
	&exactSig{[]byte("%PDF-"), PDF},
	&exactSig{[]byte("\x52\x61\x72\x21\x1A\x07\x00"), Rar},
	&exactSig{[]byte("\x52\x61\x72\x21\x1A\x07\x01\x00"), Rar}, // v5
	&exactSig{[]byte("\x50\x4B\x03\x04"), Zip},
	&exactSig{[]byte("\x1F\x8B\x08"), Gzip},
	&exactSig{[]byte("\x42\x5A\x68"), Bzip2},
	&exactSig{[]byte("\x42\x5A\x30"), Bzip},
	&exactSig{[]byte("\xFD\x37\x7A\x58\x5A\x00"), Xz},
	&exactSig{[]byte("\x04\x22\x4D\x18"), Lz4},

	&offsetSig{sig: []byte("\x75\x73\x74\x61\x72\x00\x30\x30"), offset: 257, mt: Tar},
	&offsetSig{sig: []byte("\x75\x73\x74\x61\x72\x20\x20\x00"), offset: 257, mt: Tar},
}

type exactSig struct {
	sig []byte
	mt  MIME
}

func (e *exactSig) match(data []byte) MIME {
	if bytes.HasPrefix(data, e.sig) {
		return e.mt
	}
	return Unknown
}

type offsetSig struct {
	sig    []byte
	offset int
	mt     MIME
}

func (o *offsetSig) match(data []byte) MIME {
	if len(data) < o.offset+len(o.sig) {
		return Unknown
	}
	if bytes.HasPrefix(data[o.offset:], o.sig) {
		return o.mt
	}
	return Unknown
}
