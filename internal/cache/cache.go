package cache

import (
	"encoding/json"
	"io"
	"os"

	"ipcheck/internal/models"
)

type CacheMap map[string]models.EnhancedCachedResult

// loadCache loads vt_cache.json if exists, otherwise returns empty cache
func LoadCache(path string) (CacheMap, error) {
	c := make(CacheMap)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	if err := dec.Decode(&c); err != nil && err != io.EOF {
		return nil, err
	}
	return c, nil
}

// saveCache writes cache atomically
func SaveCache(path string, c CacheMap) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}
