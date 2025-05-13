// Copyright (c) 2020-2022 TU Delft & Valentijn van de Beek <v.d.vandebeek@student.tudelft.nl> All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/baas-project/baas/pkg/model"

	"net/http"
	"os"

	usermodel "github.com/baas-project/baas/pkg/model/user"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"gorm.io/gorm"
)

var conf *oauth2.Config

func init() {
	secret := os.Getenv("GITHUB_SECRET")
	if secret == "" {
		log.Fatal("GITHUB_SECRET is not set!")
	}

	conf = &oauth2.Config{
		ClientID:     "Ov23libSvpfP4mzgI5LD",
		ClientSecret: secret,
		RedirectURL:  "http://localhost:4848/user/login/github/callback",
		Scopes:       []string{"user"},
		Endpoint:     github.Endpoint,
	}
}

func generateRandomState() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("unable to generate random state %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// returnUserByOAuth gets or creates the associated user from the database.
func (api_ *API) returnUserByOAuth(username string, email string, realName string) (*usermodel.UserModel, error) {
	user, err := api_.store.GetUserByUsername(username)
	// Create the user if we cannot find it in the database.
	if err == gorm.ErrRecordNotFound {
		user = &usermodel.UserModel{
			Username: username,
			Name:     realName,
			Email:    email,
			Role:     usermodel.User,
		}

		api_.store.CreateUser(user)
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

// LoginGithub defines the entrypoint to start the OAuth flow
func (api_ *API) LoginGithub(w http.ResponseWriter, r *http.Request) {

	// Beim Start der Authentifizierung:
	state := generateRandomState()
	log.Printf("Generated state: %s", state)
	session, err := api_.session.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	session.Values["oauth_state"] = state
	session.Save(r, w)

	url := conf.AuthCodeURL(state)
	log.Printf("Generated OAuth state: %s", state)
	log.Printf("Auth URL: %s", url)

	http.Redirect(w, r, url, http.StatusFound)
}

// LoginGithubCallback gets the token and creates the user model for the GitHub User
func (api_ *API) LoginGithubCallback(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, err := api_.session.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != session.Values["oauth_state"] {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	log.Printf("Callback received state: %s, stored state: %s", r.URL.Query().Get("state"), session.Values["oauth_state"])

	// Fetch the single-use code from the URI
	ctx := context.Background()
	code := r.URL.Query()["code"][0]
	if code == "" {
		http.Error(w, "Missing code in query", http.StatusBadRequest)
		return
	}

	// Get the OAuth token
	tok, err := conf.Exchange(ctx, code)

	if err != nil {
		log.Printf("OAuth token excange failed for code: %s: %v", code, err)
		http.Error(w, "Invalid OAuth token: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create a client which sends requests using the token.
	client := conf.Client(ctx, tok)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Request to Github API failed", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	// Fetch the user information/api.github.com/user")
	if err != nil {
		http.Error(w, "Request to GitHub API failed", http.StatusBadRequest)
		return
	}

	var loginInfo model.GitHubLogin
	if err = json.NewDecoder(resp.Body).Decode(&loginInfo); err != nil {
		http.Error(w, "Cannot parse GitHub data", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	user, err := api_.returnUserByOAuth(loginInfo.Login, loginInfo.Email, loginInfo.Email)

	if err != nil {
		http.Error(w, "Cannot find the user in the database", http.StatusBadRequest)
		return
	}

	uuID, err := uuid.NewUUID()

	if err != nil {
		http.Error(w, "Cannot generate UUID", http.StatusBadRequest)
		return
	}

	// Set the session ID and username
	session.Values["Session"] = uuID.String()
	session.Values["Username"] = user.Username
	session.Values["Role"] = string(user.Role)

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the session cookie
	http.Redirect(w, r, "http://localhost:9090/app", http.StatusFound)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
