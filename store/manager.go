package store

import (
	"bytes"
	"compute-hibp-filter/config"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/fastly/compute-sdk-go/kvstore"
)

type KVStore struct {
	Id        string `json:"id"`
	StoreName string `json:"name"`
}

type KVStoreAPIResponse struct {
	StoreList []KVStore `json:"data"`
}

func GetKVStoresMap(token string) map[string]KVStore {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.fastly.com/resources/stores/kv", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Fastly-Key", token)
	req.Header.Add("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		log.Fatal("Non-200 response code when fetching KV stores list")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		panic(err.Error())
	}

	var s = new(KVStoreAPIResponse)
	err = json.Unmarshal(body, &s)
	if err != nil {
		fmt.Println(err)
	}

	store_map := make(map[string]KVStore)
	for _, store := range s.StoreList {
		store_map[store.StoreName] = store
	}

	return store_map
}

func UploadFilterToStore(token string, store KVStore, key string, data []byte) {
	//log.Println("Uploading filter to store", store.StoreName, "(", store.Id, ")", "for key", key)
	client := &http.Client{}
	url := "https://api.fastly.com/resources/stores/kv/" + store.Id + "/keys/" + key
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Fastly-Key", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Println(string(body))
		log.Fatal("Non-200 response code when uploading filter key: " + key)
	}

}

func GetFilterBytesFromStore(hash_prefix string) ([]byte, error) {

	store_name := config.KV_STORE_NAME
	o, err := kvstore.Open(store_name)
	if err != nil {
		fmt.Println("Error opening object store", store_name, "| Error:", err.Error())
		return nil, fmt.Errorf("unable to open object store %v due to error: %v", store_name, err.Error())
	}

	entry, err := o.Lookup(hash_prefix) // Looks for AAA
	if err != nil {
		fmt.Println("Error looking up key", hash_prefix, "in object store: ", err.Error())
		return nil, fmt.Errorf("unable to lookup key %v due to error: %v", hash_prefix, err.Error())
	}

	// Read bytes from entry
	buf, err := io.ReadAll(entry)
	if err != nil {
		fmt.Println("Error reading data from object store entry: ", err.Error())
		return nil, fmt.Errorf("unable to read from entry due to error: %v", err.Error())
	}

	return buf, nil
}
