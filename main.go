package main

import (
	"bytes"
	hibp "compute-hibp-filter/hibp"
	"context"
	"crypto/sha1"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/fastly/compute-sdk-go/fsthttp"
)

//go:embed static/index.html
var index_html string

func compute_sha_hash(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
}

func main() {

	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {

		// If request is to the `/` path...
		if r.Method == "GET" && r.URL.Path == "/" {
			fsv := os.Getenv("FASTLY_SERVICE_VERSION")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, strings.ReplaceAll(index_html, "$fsv$", fsv))
			return
		} else if r.Method == "POST" && r.URL.Path == "/post" {
			// Get post parameter 'password'
			reqBody, _ := io.ReadAll(r.Body)
			password_kv := strings.Split(string(reqBody), "&")[1]
			password := strings.Split(password_kv, "=")[1]
			urldecoded_password, _ := url.QueryUnescape(password)
			password_hash := compute_sha_hash(urldecoded_password)

			pass_compromised, err := hibp.IsPasswordCompromised(password_hash)
			if err != nil {
				log.Println("Unable to verify password compromise status: ", err.Error())
			} else {
				r.Header.Add("Fastly-Compromised-Password", strconv.FormatBool(pass_compromised))
			}
			r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
		}

		resp, err := r.Send(ctx, "httpbin")
		if err != nil {
			w.WriteHeader(fsthttp.StatusBadGateway)
			fmt.Fprintln(w, err.Error())
			return
		}

		w.Header().Reset(resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)

	})
}
