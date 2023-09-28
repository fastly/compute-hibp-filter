package hibp

import (
	"compute-hibp-filter/config"
	"compute-hibp-filter/store"

	"github.com/dgryski/go-metro"
)

func IsPasswordCompromised(hash string) (bool, error) {
	prefix := hash[:3]
	filter_bytes, err := store.GetFilterBytesFromStore(prefix)
	if err != nil {
		return false, err
	}
	filter := DecodeXORFilter(filter_bytes)
	hash_uint64 := metro.Hash64([]byte(hash), config.METRO_HASH_SEED)
	result := filter.Contains(hash_uint64)

	return result, nil
}
