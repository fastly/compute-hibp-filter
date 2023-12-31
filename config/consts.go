package config

import "time"

const (
	KV_STORE_NAME                       = "hibp_filters"
	METRO_HASH_SEED                     = 1337
	MAX_RETRY_FOR_INVALID_200_RESPONSES = 5
	WAIT_TIME_FOR_INVALID_200_RESPONSES = 1 * time.Second
	HTTP_CLIENT_MAX_RETRY               = 5
	HTTP_CLIENT_RETRY_WAIT_MIN          = 1 * time.Second
	HTTP_CLIENT_RETRY_WAIT_MAX          = 30 * time.Second
)
