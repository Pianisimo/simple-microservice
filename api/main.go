package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"
)

var (
	MySigningKey = []byte(os.Getenv("SECRET_KEY"))
)

func handleRequests() {
	http.Handle("/", isAuthorized(homePage))
	log.Fatal(http.ListenAndServe(":9001", nil))
}

func main() {
	fmt.Println("server")
	handleRequests()
}

func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				_, ok := token.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					return nil, fmt.Errorf("invalid signing method")
				}
				aud := "billing.jwtgo.io"
				iss := "jwtgo.io"

				audience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
				if !audience {
					return nil, fmt.Errorf("invalid signing aud")
				}
				issuer := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !issuer {
					return nil, fmt.Errorf("invalid signing iss")
				}

				return MySigningKey, nil
			})

			if err != nil {
				fmt.Fprintf(w, err.Error())
			}

			if token.Valid {
				endpoint(w, r)
			} else {
				fmt.Fprintf(w, "\nInvalid token information")
			}
		} else {
			fmt.Fprintf(w, "No authorization token provided")
		}
	})
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Super Secret Information")
}
