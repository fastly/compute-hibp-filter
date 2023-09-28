package main

import (
	"bufio"
	"bytes"
	"compute-hibp-filter/config"
	"compute-hibp-filter/hibp"
	"compute-hibp-filter/store"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
)

func generatePrefixes(prefix_level int, start_from int64) []string {
	var prefixes []string
	combinations := math.Pow(16, float64(prefix_level))
	for i := start_from; i < int64(combinations); i++ {
		formatter_str := fmt.Sprintf("%%0%dX", prefix_level)
		prefix := fmt.Sprintf(formatter_str, i)
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func getHashesForRange(hash_prefix string) []string {
	var hashes []string
	// Get hashes from body of https://api.pwnedpasswords.com/range/C01D5
	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + hash_prefix)
	if err != nil {
		log.Fatal("Error retrieving hashes for the prefix "+hash_prefix, err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	length_of_suffix := 40 - len(hash_prefix) // 40 is the length of the sha1 hash in hex

	for scanner.Scan() {
		full_hash := hash_prefix + scanner.Text()[:length_of_suffix]
		hashes = append(hashes, full_hash)
	}
	return hashes
}

func main() {

	token := flag.String("token", "NOT_SET", "API token")
	start_from := flag.String("from", "000", "Prefix to start creating/uploading filters from")
	flag.Parse()

	if *token == "NOT_SET" {
		log.Fatal("Please provide an API token with access to upload to the KV store.")
	}
	if len(*start_from) != 3 {
		log.Fatal("Please provide a valid 3 character prefix to start creating/uploading filters from. Not specifying any will start from 000.")
	}
	start_from_int, err := strconv.ParseInt(*start_from, 16, 64)
	if err != nil {
		log.Fatal("The prefix provided is not a valid 3 digit hex number.")
		return
	}

	store_name := config.KV_STORE_NAME
	store_map := store.GetKVStoresMap(*token)
	store_obj, ok := store_map[store_name]
	if !ok {
		log.Fatal("Store " + store_name + " not found. Please create the store before attempting to upload filters.")
	}

	// Range API accepts 5 characters, and we build 3 char filters
	// So we need to generate 2 char prefixes to add to the 3 char prefixes, before querying the API
	filter_prefixes := generatePrefixes(3, start_from_int)
	hash_prefix_additions := generatePrefixes(2, 0)
	for _, filter_prefix := range filter_prefixes {
		var hashes_for_filter []string
		log.Println("Getting hashes for prefix", filter_prefix)

		// Get hashes for the prefix in parallel (256 HTTP calls for a single filter_prefix)
		queue := make(chan *[]string, len(hash_prefix_additions))
		for _, hash_prefix_addition := range hash_prefix_additions {
			hash_prefix := filter_prefix + hash_prefix_addition
			go func(hash_prefix string) {
				hashes := getHashesForRange(hash_prefix)
				queue <- &hashes
			}(hash_prefix)
		}
		// Wait for all goroutines to finish and collect the hashes for the fitler
		for i := 0; i < len(hash_prefix_additions); i++ {
			hashes := <-queue
			hashes_for_filter = append(hashes_for_filter, *hashes...)
		}
		// Build filter for the prefix
		log.Println("Building filter for prefix", filter_prefix, "with", len(hashes_for_filter), "hashes")
		filter := hibp.CreateFilterWithHashes(filter_prefix, hashes_for_filter)

		// Write filter to KV store
		var b bytes.Buffer
		w := bufio.NewWriter(&b) // Alternatively use a file handle to write to a file
		hibp.WriteFilterToWriter(filter, w)
		data := b.Bytes()
		log.Println("Uploading filter for prefix", filter_prefix, "with size:", len(data))
		store.UploadFilterToStore(*token, store_obj, filter_prefix, data)
	}

	log.Println("Done uplaoding filters to store", config.KV_STORE_NAME, "with store_id", store_obj.Id)

}
