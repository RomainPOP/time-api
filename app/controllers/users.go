package controllers

import (
	"fmt"
	"log"
	"net/http"
	"time"
	"time-api/app/models"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/revel/revel"
	gormc "github.com/revel/modules/orm/gorm/app/controllers"

)

type Users struct {
	*revel.Controller
	gormc.TxnController
}

var hmacSecret = []byte{97, 48, 97, 50, 97, 98, 105, 49, 99, 102, 83, 53, 57, 98, 52, 54, 97, 102, 99, 12, 12, 13, 56, 34, 23, 16, 78, 67, 54, 34, 32, 21}

// Register create a user and returns token to client.
// params: email, password
// result: token with user.id stores in `sub` field.
func (c Users) Register() revel.Result {
	// create user use, email, password
	// return token to user
	var jsondata map[string]string
	c.Params.BindJSON(&jsondata)
	email := jsondata["email"]
	password := jsondata["password"]

	//
	if email == "" || password == "" {
		// this is not json
		c.Response.Status = http.StatusBadRequest
		error := models.Error{"Email or password empty", "params is not valid", http.StatusBadRequest}
		return c.RenderJSON(error)
	}

	// check if the email have already exists in DB
	results := []models.User{}
	DB.Where("email = ?", email).Find(&results)
	//results := DB.Select(models.User{}, `select * from User where Email = ?`, email)
	/*err := results.Error
	if err != nil {
		log.Println(err)
	}*/
	var users []*models.User
	for _, r := range results {
		//u := r.(*models.User)
		users = append(users, &r)
	}
	if users != nil {
		c.Response.Status = http.StatusConflict
		error := models.Error{"user already exist", "user already exist", http.StatusConflict}
		return c.RenderJSON(error)
	}

	// Crete user struct
	bcryptPassword, _ := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)

	token := encodeToken(email)

	newUser := &models.User{ "Demo User", email, password, bcryptPassword, []byte(token)}

	// Validate user struct
	newUser.Validate(c.Validation)
	if c.Validation.HasErrors() {
		log.Println(c.Validation.Errors[0].Message)
		c.Response.Status = http.StatusBadRequest
		error := models.Error{c.Validation.Errors[0].Message, "bad email address", http.StatusBadRequest}
		return c.RenderJSON(error)
	}

	// Save user info to DB
	result := DB.Create(newUser)
	if err := result.Error; err != nil {
		panic(err)
	}

	msg := make(map[string]string)
	msg["email"] = email
	msg["result"] = "user created"
	msg["token"] = token
	return c.RenderJSON(msg)
}

// Login authticate via email and password, if the user is valid,
// returns the token to client.
func (c Users) Login() revel.Result {
	log.Println("login")
	var jsondata map[string]string
	c.Params.BindJSON(&jsondata)
	email := jsondata["email"]
	password := jsondata["password"]
	//email := c.Params.Get("email")
	//password := c.Params.Get("password")

	user, err := getUser(email)
	if err != nil {
		log.Println(err)
		c.Response.Status = http.StatusBadRequest
		errorMsg := models.Error{ err.Error(), "invalid email", http.StatusBadRequest}
		return c.RenderJSON(errorMsg)
	}

	error := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password))
	if error != nil {
		log.Println(error)
		c.Response.Status = http.StatusBadRequest
		errorPass := models.Error{error.Error(), "invalid password", http.StatusBadRequest}
		return c.RenderJSON(errorPass)
	}

	// get token
	tokenString := encodeToken(email)

	msg := make(map[string]string)
	msg["result"] = "login success"
	msg["token"] = tokenString
	c.Response.Status = http.StatusCreated
	return c.RenderJSON(msg)
}

func getUser(email string) (*models.User, error) {
	log.Println("search user : ", email)
	user := models.User{}
	err := DB.Where("email = ?", email).First(&user).Error
	//users := DB.Select(models.User{}, `select * from User where Email = ?`, email)
	log.Println(err)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Println("user finded")
	/*if  {
		return nil, errors.New("user not found")
	}*/
	return &user, nil
}

func encodeToken(email string) string {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"nbf":   time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSecret)

	fmt.Println(tokenString, err)

	return tokenString
}

func decodeToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSecret, nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		fmt.Println("email and nbf:", claims["email"], claims["nbf"])
	} else {
		log.Println(err)
		return nil, err
	}
	return claims, nil
	// return claims["email"].(string), claims["nbf"].(string)
}