package common

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/pkg/sftp"
)

func Glob(client *sftp.Client, pattern string) (matches []string, err error) {
	if !hasMeta(pattern) {
		if _, err = client.Lstat(pattern); err != nil {
			return nil, nil
		}
		return []string{pattern}, nil
	}

	dir, file := filepath.Split(pattern)
	volumeLen := 0
	dir = cleanGlobPath(dir)

	if !hasMeta(dir[volumeLen:]) {
		return glob(client, dir, file, nil)
	}

	// Prevent infinite recursion. See issue 15879.
	if dir == pattern {
		return nil, filepath.ErrBadPattern
	}

	var m []string
	m, err = Glob(client, dir)
	if err != nil {
		return
	}
	for _, d := range m {
		matches, err = glob(client, d, file, matches)
		if err != nil {
			return
		}
	}
	return
}

// cleanGlobPath prepares path for glob matching.
func cleanGlobPath(path string) string {
	switch path {
	case "":
		return "."
	case string(filepath.Separator):
		// do nothing to the path
		return path
	default:
		return path[0 : len(path)-1] // chop off trailing separator
	}
}

func glob(client *sftp.Client, dir, pattern string, matches []string) (m []string, e error) {
	m = matches
	fi, err := client.Stat(dir)
	if err != nil {
		return
	}
	if !fi.IsDir() {
		return
	}
	infos, err := client.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		matched, err := filepath.Match(pattern, n)
		if err != nil {
			return m, err
		}
		if matched {
			m = append(m, filepath.Join(dir, n))
		}
	}
	return
}

// hasMeta reports whether path contains any of the magic characters
// recognized by Match.
func hasMeta(path string) bool {
	magicChars := `*?[`
	return strings.ContainsAny(path, magicChars)
}
