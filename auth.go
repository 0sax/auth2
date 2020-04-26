// auth handles session/token based authentication on firebase DataStore
// to initialise package an InitAuthVariables struct must be created and the initialized
// in main.
//
// Usage:
//	Package must variables must be initialized before main.go runs
//
// 	Required Collections
//	 1. "users" stores user data.
//			Required Fields:
//				*"email": must be unique
//				*"password": contains MD5 hash of the password
//	 2. "sessions" stores session data.
//			Required Fields:
//				*"email"
//				*"expiryDate": when the session is no longer considered valid
//					you can run a cron to sweep through and delete sessions
//					with an expiryDate before time.Now() or use the
//					DeleteDeadSessions() function
//				*"role": the session user's role

package auth2

import (
	"cloud.google.com/go/firestore"
	"context"
	"fmt"
	"net/http"
)

const (
	ErrNoEmail          = 1  // No Email
	ErrNoPassword       = 2  // No Password
	ErrInitVars         = 3  // Initialization variable error
	ErrNoUser           = 4  // User does not exist
	ErrDuplicateUser    = 5  // Two users exist with email
	ErrParseError       = 6  // Parse Error
	ErrWrongPassword    = 7  // Wrong Password
	ErrNoSessionCreated = 9  // Couldn't create a session
	ErrUserNotApproved  = 10 // User has not been approved yet
	ErrNoSession        = 11 // Session doesn't exist
)

var av *InitAuthVariables

// InitAuthVariables is a holder for the auth initialization variables
type InitAuthVariables struct {
	CookieName        string            // *Required* used to store user sessions
	FlashCookieName   string            // *Required* Used to display flashes to the user
	DBName            *firestore.Client // *Required* Firestore client connection
	RedirectOnSignIn  string            // *Required* Route user is redirected to, on Sign in
	RedirectOnLogOut  string            // *Required* Route user is redirected to, on Logout
	redirectIfNoRight string            // *Required* Route user is redirected to, if they lack permission
	SessionLife       int               // *Required* How long a session should live on the server (seconds)
	GCContext         context.Context   // *Required* GCloud context
	CookieEncoding    string            //Encoding Key //
	SessionsTable     string
	UsersTable        string
}

// Init initializes the package based on variables defined in the
// InitAuthVariables struct
func (iav *InitAuthVariables) Init() error {
	var err string
	if iav.CookieName == "" {
		err = "no name provided for session cookie"
	} else if iav.FlashCookieName == "" {
		err = "no name provided for flash cookie"
	} else if iav.DBName == nil {
		err = "no firestore client provided"
	} else if iav.SessionLife == 0 {
		err = "session life not set"
	} else if iav.GCContext == nil {
		err = "no GC context provided"
	} else if iav.SessionsTable == "" {
		err = "no session table name provided"
	} else if iav.UsersTable == "" {
		err = "no user table name provided"
	}

	if err != "" {
		return &Error{
			Msg:     err,
			ErrType: ErrInitVars,
		}
	}

	av = iav
	return nil
}

// Error handles errors for this package
type Error struct {
	Msg      string
	ErrType  int
	Ancestor error
}

// Error implements the error interface
func (sE Error) Error() string {
	return fmt.Sprintf(sE.Msg)
}

// AuthMiddleware keeps unauthorized users from accessing the provided handler
// next: is the destination handler
// roles: is a list of the roles authorized to access handler
// rdr: is the route user is redirected to if they lack access rights
func AuthMiddleware(next func(w http.ResponseWriter, r *http.Request),
	roles []string, rdr string) http.Handler {

	var rdr2 string
	if rdr == "" {
		rdr2 = av.RedirectOnLogOut
	} else {
		rdr2 = rdr
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			// 1. Get cookie
			c, err := r.Cookie(av.CookieName)
			if err != nil {
				if err == http.ErrNoCookie {
					fmt.Println("Client didn't send a cookie:", err)
					//todo: handle better
					http.Redirect(w, r, rdr2, http.StatusUnauthorized)
					return
				}
				fmt.Println("Didn't work for other reason:", err)
				//todo: handle better
				http.Redirect(w, r, rdr2, http.StatusUnauthorized)
				return
			}
			// 1.b. get session token from cookie
			sessionToken := c.Value

			// 2. Get session details from FireStore
			s, err := GetSession(sessionToken)
			if err != nil {
				fmt.Println("error getting session details", err)
				//todo: handle better
				http.Redirect(w, r, rdr2, http.StatusForbidden)
				return
			}

			// 3. Check if user has access
			if s.CanAccess(roles) != true {
				fmt.Println("User does not have the necessary privileges to view this page")
				//todo: handle better
				http.Redirect(w, r, r.Header.Get("Referer"), http.StatusForbidden)
				return
			}

			next(w, r)

		})

}
