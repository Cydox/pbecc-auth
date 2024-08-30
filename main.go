package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	//"io"
	"net/http"
)

type user struct {
	name      string
	salt      []byte
	publicKey []byte
}

var u user
var c [32]byte

type signup_struct struct {
	PublicKey string `json:"publickey"`
	Salt      string `json:"salt"`
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var data signup_struct
	err := decoder.Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	salt, err := base64.StdEncoding.DecodeString(data.Salt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	publicKey, err := base64.StdEncoding.DecodeString(data.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	u.name = "admin"
	u.salt = salt
	u.publicKey = publicKey

	fmt.Println("Sign up")
	fmt.Println(u)

}

type challenge_struct struct {
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"`
}

func getChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var ch challenge_struct
	encoder := json.NewEncoder(w)

	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ch.Salt = base64.StdEncoding.EncodeToString(u.salt)
	ch.Challenge = base64.StdEncoding.EncodeToString(challenge)

	err = encoder.Encode(ch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("challenge")
	fmt.Println(ch)

	copy(c[:], challenge[:32])
}

type signin_struct struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var data signin_struct
	err := decoder.Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	challenge, err := base64.StdEncoding.DecodeString(data.Challenge)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(data.Signature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("signin")
	fmt.Println(data)

	if !bytes.Equal(challenge, c[:]) {
		http.Error(w, "incorrect challenge", http.StatusBadRequest)
		return
	}

	pubKey := ed25519.PublicKey(u.publicKey)
	if !ed25519.Verify(pubKey, c[:], signature) {
		fmt.Println("signature verification failed!")
		http.Error(w, "signature verification failed!", http.StatusUnauthorized)
		return
	}

	fmt.Println("signature verification succesful!")
	fmt.Fprintln(w, "signature verification succesful!")

}

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/getchallenge", getChallengeHandler)
	http.HandleFunc("/signin", signinHandler)

	fmt.Println("Starting server on :1337")
	if err := http.ListenAndServe(":1337", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
