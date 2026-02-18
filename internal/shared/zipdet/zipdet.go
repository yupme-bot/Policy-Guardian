package zipdet

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"sort"
	"time"
)

var FixedTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

type Entry struct {
	Name string
	Data []byte
}

func WriteDeterministicZip(entries []Entry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("no entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for i := range entries {
		if entries[i].Name == "" || entries[i].Name[0] == '/' {
			return nil, errors.New("invalid entry name")
		}
		if bytes.Contains([]byte(entries[i].Name), []byte(`\`)) {
			return nil, errors.New("backslash not allowed in zip path")
		}
		if i > 0 && entries[i].Name == entries[i-1].Name {
			return nil, errors.New("duplicate entry name")
		}
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.Name, Method: zip.Store}
		h.SetModTime(FixedTime)
		h.CreatorVersion = 20
		h.ReaderVersion = 20
		wr, err := zw.CreateHeader(h)
		if err != nil {
			zw.Close()
			return nil, err
		}
		if _, err := io.Copy(wr, bytes.NewReader(e.Data)); err != nil {
			zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
