// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package oauthprompt implements prompting a local user for
// an OAuth token and caching the result in the user's home directory.
package oauthprompt

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/oauth2"
	oauth "golang.org/x/oauth2"
)

// Token obtains an OAuth token, keeping a cached copy in file.
// If the file name is not an absolute path, it is interpreted relative to the
// user's home directory.
func Token(file string, cfg *oauth.Config) (*http.Client, error) {
	if !filepath.IsAbs(file) {
		file = filepath.Join(os.Getenv("HOME"), file)
	}
	data, err := os.ReadFile(file)
	if err == nil {
		var tok oauth.Token
		if err := json.Unmarshal(data, &tok); err != nil {
			return nil, fmt.Errorf("oauthprompt.Token: unmarshal %s: %v", file, err)
		}
		return cfg.Client(context.Background(), &tok), nil
	}

	// Start HTTP server on localhost.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		var err1 error
		if l, err1 = net.Listen("tcp6", "[::1]:0"); err1 != nil {
			return nil, fmt.Errorf("oauthprompt.Token: starting HTTP server: %v", err)
		}
	}

	type done struct {
		err  error
		code string
	}
	ch := make(chan done, 100)

	randState, err := randomID()
	if err != nil {
		return nil, err
	}

	cfg1 := *cfg
	cfg = &cfg1
	cfg.RedirectURL = "http://" + l.Addr().String() + "/done"
	authURL := cfg1.AuthCodeURL(randState)

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/auth" {
			http.Redirect(w, req, authURL, 301)
			return
		}
		if req.URL.Path != "/done" {
			http.Error(w, "", 404)
			return
		}
		if req.FormValue("state") != randState {
			ch <- done{err: fmt.Errorf("oauthprompt.Token: incorrect response")}
			http.Error(w, "", 500)
			return
		}
		if code := req.FormValue("code"); code != "" {
			ch <- done{code: code}
			w.Write([]byte(success))
			return
		}
		http.Error(w, "", 500)
	})

	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	if err := openURL("http://" + l.Addr().String() + "/auth"); err != nil {
		l.Close()
		return nil, err
	}
	d := <-ch
	l.Close()

	if d.err != nil {
		return nil, err
	}

	tok, err := cfg.Exchange(context.Background(), d.code)
	if err != nil {
		return nil, err
	}

	data, err = json.Marshal(tok)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(file, data, 0666); err != nil {
		return nil, err
	}

	return cfg.Client(context.Background(), tok), nil
}

var browsers = []string{
	"xdg-open",
	"google-chrome",
	"open", // for OS X
}

func openURL(url string) error {
	fmt.Fprintf(os.Stderr, "oauthprompt: %s\n", url)
	for _, browser := range browsers {
		err := exec.Command(browser, url).Run()
		if err == nil {
			return nil
		}
	}

	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		// Hope for the best with standard error.
		tty = os.Stderr
	} else {
		defer tty.Close()
	}

	_, err = fmt.Fprintf(tty, "To log in, please visit %s\n", url)
	if err != nil {
		return fmt.Errorf("failed to notify user about URL")
	}
	return nil
}

// GoogleToken is like Token but assumes the Google AuthURL and TokenURL,
// so that only the client ID and secret and desired scope must be specified.
func GoogleToken(file, clientID, clientSecret string, scopes ...string) (*http.Client, error) {
	cfg := &oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}
	return Token(file, cfg)
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("RandomID: reading rand.Reader: %v", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

var success = `<html>
<head>
<title>Authenticated</title>
<script>
function done() {
	setTimeout(function() {window.close()}, 5000)
}
</script>
</head>
<body onload="done()">
Thanks for authenticating.
</body>
</html>
`
