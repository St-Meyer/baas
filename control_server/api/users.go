// Copyright (c) 2020-2022 TU Delft & Valentijn van de Beek <v.d.vandebeek@student.tudelft.nl> All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	usermodel "github.com/baas-project/baas/pkg/model/user"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func _getUserInternal(w http.ResponseWriter, r *http.Request, api *API) (*usermodel.UserModel, error) {
	session, _ := api.session.Get(r, "session-name")
	username, ok := session.Values["Username"].(string)
	if !ok {
		http.Error(w, "Username not found", http.StatusBadRequest)
		return nil, errors.New("username not found")
	}

	vars := mux.Vars(r)
	name, ok := vars["name"]
	if !ok || name == "" {
		http.Error(w, "name not found", http.StatusBadRequest)
		log.Errorf("name not provided in get user")
		return nil, errors.New("name not found")
	}

	user, err := api.store.GetUserByUsername(name)

	// Annoyingly enough we can't be more specific due to error wrapping... I swear, this language.
	if err != nil {
		http.Error(w, "couldn't get users", http.StatusInternalServerError)
		log.Errorf("get users: %v", err)
		return nil, err
	}

	// Check if the user is allowed to access the profile.
	if user.Role != usermodel.Admin && user.Username != username {
		http.Error(w, "Cannot access this user", http.StatusUnauthorized)
		return nil, err
	}
	return user, nil
}

// GetUsers fetches all the users from the database
// Example request: users
// Response: [{"Name": "Valentijn", "Email": "v.d.vandebeek@student.tudelft.nl",
//
//	"Role": "admin", "Image": null}
func (api_ *API) GetUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := api_.store.GetUsers()

	if err != nil {
		http.Error(w, "couldn't get users", http.StatusInternalServerError)
		log.Errorf("get users: %v", err)
		return
	}

	_ = json.NewEncoder(w).Encode(users)
}

// CreateUser creates a new user in the database
// Example request: user, {"name": "William Narchi",
//
//	"email", "w.narchi1@student.tudelft.nl",
//	"role": "user"}
//
// Response: Either an error message or success.
func (api_ *API) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user usermodel.UserModel
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		http.Error(w, "invalid user given", http.StatusBadRequest)
		log.Errorf("Invalid user given: %v", err)
		return
	}

	if user.Username == "" {
		http.Error(w, "No username given", http.StatusBadRequest)
		return
	}

	if user.Name == "" {
		http.Error(w, "No name given", http.StatusBadRequest)
		return
	}

	if user.Email == "" {
		http.Error(w, "No email given", http.StatusBadRequest)
		return
	}

	if user.Role == "" {
		http.Error(w, "No role given", http.StatusBadRequest)
		return
	}

	err = api_.store.CreateUser(&user)
	if err != nil {
		http.Error(w, "couldn't create user", http.StatusInternalServerError)
		log.Errorf("create user: %v", err)
		return
	}
	_, err = fmt.Fprintf(w, "Successfully created user\n")
	if err != nil {
		log.Error("Error writing over http")
		return
	}
}

// GetLoggedInUser gets the currently logged-in user and returns it.
// Example request: user/me
func (api_ *API) GetLoggedInUser(w http.ResponseWriter, r *http.Request) {
	session, _ := api_.session.Get(r, "session-name")
	username, ok := session.Values["Username"].(string)

	if !ok {
		http.Error(w, "Cannot find username", http.StatusBadRequest)
		return
	}

	user, err := api_.store.GetUserByUsername(username)

	if err != nil {
		http.Error(w, "Cannot find user: "+username, http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(user)
}

// GetImagesByName gets any image based on the user who created it and human-readable name assigned to it.
// Example Request: user/Jan/images/Gentoo
// Example Response: [
//
//	{
//	  "Name": "Gentoo",
//	  "Versions": null,
//	  "UUID": "57bf0cd3-c2bf-4257-acdd-b7f1c8633fcf",
//	  "DiskUUID": "30DF-844C",
//	  "UserModelID": 1
//	}
//
// ]
func (api_ *API) GetImagesByName(w http.ResponseWriter, r *http.Request) {
	username, err := GetName(w, r)
	if err != nil {
		http.Error(w, "Couldn't find images by name.", http.StatusInternalServerError)
		log.Errorf("could not find name in request: %v", err)
		return
	}

	imageName, err := GetTag("image_name", w, r)
	if err != nil {
		http.Error(w, "Couldn't find images by name.", http.StatusInternalServerError)
		log.Errorf("could not find image name in request: %v", err)
		return
	}

	userImages, err := api_.store.GetImagesByNameAndUsername(imageName, username)

	if err != nil {
		http.Error(w, "couldn't get image", http.StatusInternalServerError)
		log.Errorf("get image by name: %v", err)
		return
	}

	_ = json.NewEncoder(w).Encode(userImages)
}

// GetImagesByUser fetches all the images of the given user
// Example request: user/Jan/images
// Example result: [
//
//	{
//	  "Name": "Windows",
//	  "Versions "a9c11954-6161-410b-b238-c03df5c529e9",
//	  "DiskUUID": "30DF-844C",
//	  "UserModelID": 2
//	},
//	{
//	  "Name": "Arch Linux",
//	  "Versions": null,
//	  "UUID": "341b2c69-8776-4e54-9330-7c9692f7ed28",
//	  "DiskUUID": "30DF-844C",
//	  "UserModelID": 2
//	}
//
// ]
func (api_ *API) GetImagesByUser(w http.ResponseWriter, r *http.Request) {
	name, err := GetName(w, r)
	if err != nil {
		return
	}

	userImages, err := api_.store.GetImagesByUsername(name)

	if err != nil {
		http.Error(w, "couldn't get userImages", http.StatusInternalServerError)
		log.Errorf("get userImages by users: %v", err)
		return
	}

	_ = json.NewEncoder(w).Encode(userImages)
}

// GetUser fetches a user based on their name and returns it
// Example request: GET /user/[name]
// Response: {"Name": "Jan",
//
//	"Email": "v.d.vandebeek@student.tudelft.nl",
//	"role": "admin"}
func (api_ *API) GetUser(w http.ResponseWriter, r *http.Request) {
	user, err := _getUserInternal(w, r, api_)
	if err != nil {
		return
	}
	_ = json.NewEncoder(w).Encode(user)
}

// DeleteUser removes a user from the database
// Request: DELETE /user/[name]
// Response: Successfully deleted user
func (api_ *API) DeleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := _getUserInternal(w, r, api_)
	if err != nil {
		return
	}

	err = api_.store.RemoveUser(user)
	if err != nil {
		http.Error(w, "Cannot remove the user.", http.StatusBadRequest)
		log.Errorf("Remove user: %v", err)
		return
	}

	http.Error(w, "Successfully deleted user", http.StatusOK)
}

// ModifyUser modifies the metadata related to the user
// Request: PUT /user/[name]
// Response: the modified user
func (api_ *API) ModifyUser(w http.ResponseWriter, r *http.Request) {
	oldUser, err := _getUserInternal(w, r, api_)
	if err != nil {
		return
	}

	newUser := usermodel.UserModel{}
	err = json.NewDecoder(r.Body).Decode(&newUser)
	newUser.Username = oldUser.Username
	if err != nil {
		http.Error(w, "Cannot decode the request body.", http.StatusBadRequest)
		log.Errorf("Modify user: %v", err)
		return
	}

	err = api_.store.ModifyUser(&newUser)
	if err != nil {
		http.Error(w, "Cannot decode the request body.", http.StatusBadRequest)
		log.Errorf("Modify user: %v", err)
		return
	}

	_ = json.NewEncoder(w).Encode(newUser)
}

// RegisterUserHandlers sets the metadata for each of the routes and registers them to the global handler
func (api_ *API) RegisterUserHandlers() {
	api_.Routes = append(api_.Routes, Route{
		URI:         "/users",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: false,
		Handler:     api_.GetUsers,
		Method:      http.MethodGet,
		Description: "Gets all the users from the database",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user",
		Permissions: []usermodel.UserRole{usermodel.Admin},
		UserAllowed: false,
		Handler:     api_.CreateUser,
		Method:      http.MethodPost,
		Description: "Adds a new user to the database",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/me",
		Permissions: []usermodel.UserRole{usermodel.User, usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.GetLoggedInUser,
		Method:      http.MethodGet,
		Description: "Gets the user who is currently logged in",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/{name}",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.GetUser,
		Method:      http.MethodGet,
		Description: "Gets information about a particular user",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/{name}",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.DeleteUser,
		Method:      http.MethodDelete,
		Description: "Deletes a user from the database",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/{name}",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.ModifyUser,
		Method:      http.MethodPut,
		Description: "Gets information about a particular user",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/{name}/image",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.CreateImage,
		Method:      http.MethodPost,
		Description: "Creates a new image",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/{name}/images",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.GetImagesByUser,
		Method:      http.MethodGet,
		Description: "Gets all the images owned by a particular user",
	})

	api_.Routes = append(api_.Routes, Route{
		URI:         "/user/{name}/images/{image_name}",
		Permissions: []usermodel.UserRole{usermodel.Moderator, usermodel.Admin},
		UserAllowed: true,
		Handler:     api_.GetImagesByName,
		Method:      http.MethodGet,
		Description: "Finds all the images by this user with a particular name",
	})
}
