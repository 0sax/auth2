package auth2

import (
	"cloud.google.com/go/firestore"
	"errors"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"net/smtp"
	"strconv"
)

// User is a holder struct for carrying user details to and from various functions as needed
type User struct {
	Email    string      `firestore:"email,omitempty"`
	Password string      `firestore:"password,omitempty"`
	UserID   string      `firestore:"userID,omitempty"`
	Role     string      `firestore:"role,omitempty"`
	Approved bool        `firestore:"approved,omitempty"`
	Data     interface{} `firestore:"data,omitempty"` //optional field for app specific data
	IPAddr   string
}

// Create creates a new user and logs to the database
// If customID is true, document ID will be set to the UserID specified
// in the struct
func (u *User) Create(customID bool) error {

	_, err := u.GetUserSnapshot()
	if err != nil && err.(*Error).ErrType != ErrNoUser {
		return errors.New("user with this email address already exists")
	}

	// 1. Generate Password hash
	pass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("Password hashing failed" + err.Error())
	}

	u.Password = string(pass)

	switch customID {
	case true:
		//If id setting is custom,
		// Check if ID is present
		if u.UserID == "" {
			return errors.New("custom ID set as \"true\" yet no ID was provided")
		}
		// check if that ID already exists
		_, err := av.DBName.Collection(av.UsersTable).Doc(u.UserID).Get(av.GCContext)
		switch {
		case err != nil:
			switch {
			case status.Code(err) == codes.NotFound:
				//create a new one
				_, err := av.DBName.Collection(av.UsersTable).Doc(u.UserID).
					Set(av.GCContext, u)
				if err != nil {
					return errors.New("could not create user because: " + err.Error())
				}
			default:
				return errors.New("could not create user because: " + err.Error())
			}
		case err == nil:
			return errors.New("a user with this id already exists in database: ")
		}
	case false:
		//if not, use add
		_, _, err = av.DBName.Collection(av.UsersTable).Add(av.GCContext, u)
		if err != nil {
			return err
		}
	}

	// 2. Add User
	return nil
}

//GetUserSnapshot pulls up the firestore.DocumentSnapshot for User u
func (u *User) GetUserSnapshot() (*firestore.DocumentSnapshot, error) {
	if u.Email == "" {
		return nil, &Error{Msg: "please provide an email address",
			ErrType: ErrNoEmail}
	}

	usr, err := av.DBName.Collection(av.UsersTable).Where("email", "==", u.Email).
		Documents(av.GCContext).GetAll()
	if err != nil {
		return nil, &Error{
			Msg:     "error querying db for user: " + u.Email + "because: " + err.Error(),
			ErrType: ErrDB,
		}
	}

	if len(usr) == 0 {
		return nil, &Error{
			Msg:     "User " + u.Email + "does not exist",
			ErrType: ErrNoUser,
		}
	}

	if len(usr) > 1 {
		return nil, &Error{
			Msg: "there are " + strconv.Itoa(len(usr)) +
				" users with this email address, contact admin",
			ErrType: ErrDuplicateUser,
		}
	}

	return usr[0], nil

}

// DataTo parses nested maps to a struct i
func (u *User) DataTo(s interface{}) error {
	//decode to struct
	err := mapstructure.Decode(u.Data, &s)
	if err != nil {
		return err
	}

	return nil
}

// Edit Changes user details to those defined in the User struct
// All non-zero values will overwrite existing values
func (u User) Edit() error {
	usr, err := u.GetUserSnapshot()
	if err != nil {
		return err
	}
	_, err = usr.Ref.Set(av.GCContext, u, firestore.Merge())
	if err != nil {
		return err
	}
	return nil
}

// UpdateFromSession uses the GetSession function to
// ...get the session details, and parses the returned session
// to a User struct
func (u *User) UpdateFromSession(s string) error {
	m, err := GetSession(s)
	if err != nil {
		return errors.New("Unable to get user details because: " + err.Error())
	}
	u.Email = m.Email
	u.Role = m.Role
	u.Data = m.Data
	u.IPAddr = m.IPAddr
	return nil
}

// SignIn confirms that the entered User credentials (email and password)
// match what is in the Firestore, creates a session for the user on the server,
// and returns a cookie containing the session token
func (u *User) SignIn() (*http.Cookie, error) {
	if u.Email == "" {
		return nil, &Error{Msg: "please provide an email address",
			ErrType: ErrNoEmail}
	}
	if u.Password == "" {
		return nil, &Error{Msg: "please provide a password",
			ErrType: ErrNoPassword}
	}
	pw := u.Password

	// check for user
	usr, err := u.GetUserSnapshot()
	if err != nil {
		return nil, err
	}

	var u2 *User

	err = usr.DataTo(&u2)
	if err != nil {
		return nil, &Error{
			Msg:      "error parsing user details to user struct: " + err.Error(),
			ErrType:  ErrParseError,
			Ancestor: err,
		}
	}

	if u2.Approved != true {
		return nil, &Error{
			Msg:     "user account not yet approved",
			ErrType: ErrUserNotApproved,
		}
	}

	//compare password
	err = bcrypt.CompareHashAndPassword([]byte(u2.Password), []byte(pw))
	if err != nil {
		return nil, &Error{
			Msg:      "Wrong Password",
			ErrType:  ErrWrongPassword,
			Ancestor: err,
		}
	}

	// Add IP Address to u2
	u2.IPAddr = u.IPAddr

	// create session
	c, err := CreateSession(u2, av.CookieName, av.SessionLife)
	if err != nil {
		fmt.Println(err)
		return nil, &Error{
			Msg:      "login error, contact admin",
			ErrType:  ErrNoSessionCreated,
			Ancestor: err,
		}
	}

	u.Data = u2.Data
	u.Password = ""

	return c, nil
}

//ChangePasword will change a user's password, u struct only needs
// email address and password field to be populated
func (u *User) ChangePassword(newPassword string) error {

	// Get snapshot
	u1, err := u.GetUserSnapshot()
	if err != nil {
		return err // custom error
	}

	// Parse to User struct
	var u2 User
	err = u1.DataTo(&u2)
	if err != nil {
		return &Error{
			Msg:      "error parsing user details to user struct: " + err.Error(),
			ErrType:  ErrParseError,
			Ancestor: err,
		}
	}

	// Compare old password with current password
	err = bcrypt.CompareHashAndPassword([]byte(u2.Password), []byte(u.Password))
	if err != nil {
		return &Error{
			Msg:      "Wrong Password",
			ErrType:  ErrWrongPassword,
			Ancestor: err,
		}
	}
	// Generate hash for new password
	pass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("Password hashing failed" + err.Error())
	}

	// Update password field with new hash
	_, err = u1.Ref.Update(av.GCContext, []firestore.Update{{Path: "password", Value: string(pass)}})
	if err != nil {
		return err
	}

	fmt.Println("password change successful")
	return nil

}

//ChangePasword will reset a user's password, u struct only needs
// email address and password field to be populated
// returns newPassword as a string
func (u *User) ResetPassword() (string, error) {

	// Get snapshot
	u1, err := u.GetUserSnapshot()
	if err != nil {
		return "", err // custom error
	}
	// generate random string
	tempPass := randomString(6)
	// Create hash from random string
	pass, err := bcrypt.GenerateFromPassword([]byte(tempPass), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("Password hashing failed" + err.Error())
	}
	// Update password field with new hash
	_, err = u1.Ref.Update(av.GCContext, []firestore.Update{{Path: "password", Value: string(pass)}})
	if err != nil {
		return "", err
	}
	fmt.Println("password reset successful")

	return tempPass, nil

}

//Comment

type EmailParams struct {
	From string
	Pass string
	Host string
	Port string
}

func (u *User) SendResetMailer(message, password string, emp EmailParams) error {

	from := emp.From
	pass := emp.Pass
	host := emp.Host
	port := emp.Port

	to := []string{u.Email}

	msg := message + "\n \n Your temporary password is: " + password +
		"\n Please change this as soon as you sign in"

	auth := smtp.PlainAuth("", from, pass, host)

	err := smtp.SendMail(host+":"+port, auth, from, to, []byte(msg))
	if err != nil {
		return err
	}

	fmt.Println("Email Sent!")
	return nil

}
