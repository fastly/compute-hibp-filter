package hibp

import (
	"compute-hibp-filter/config"
	"compute-hibp-filter/store"
	"log"

	"github.com/dgryski/go-metro"
)

func IsPasswordCompromised(hash string) (bool, error) {
	log.Println("Verifying password compromise status for hash: ", hash)
	prefix := hash[:3]
	log.Println("Retrieving filter from KV store using key:", prefix)
	filter_bytes, err := store.GetFilterBytesFromStore(prefix)
	if err != nil {
		return false, err
	}
	log.Println("Retrieved filter of size:", len(filter_bytes), "bytes. Decoding filter...")
	filter := DecodeXORFilter(filter_bytes)
	hash_uint64 := metro.Hash64([]byte(hash), config.METRO_HASH_SEED)
	result := filter.Contains(hash_uint64)
	log.Println("Looking up metro hash of password hash in filter. Is hash in filter:", result)

	return result, nil
}
