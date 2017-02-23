package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
	"github.com/urfave/cli"
	books "google.golang.org/api/books/v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type H map[string]interface{}

var session *mgo.Session
var authTokenCookieName = "auth-token"
var dbname string

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	var files []string
	files = append(files, "templates/base.html")
	files = append(files, fmt.Sprintf("templates/%s.html", name))
	tmpl := template.Must(template.ParseFiles(files...))
	return tmpl.Execute(w, data)
}

type User struct {
	ID                 bson.ObjectId `bson:"_id"`
	NickName           string
	TwitterID          string
	SessionKey         string
	TwitterAccessToken string
	TwitterAvatarURL   string
	Name               string
	City               string
	State              string
}

type Book struct {
	ID             bson.ObjectId `bson:"_id"`
	ApiID          string
	SmallThumbnail string
	Title          string
	Owner          string
}

type Trade struct {
	ID             bson.ObjectId `bson:"_id"`
	User1ID        string
	User2ID        string
	Book1ID        bson.ObjectId
	Book2ID        bson.ObjectId
	Book1Title     string
	Book2Title     string
	Book1Thumbnail string
	Book2Thumbnail string
}

func NewUserFromGothUser(gothUser goth.User) *User {
	u := new(User)
	u.ID = bson.NewObjectId()
	u.NickName = gothUser.NickName
	u.TwitterID = gothUser.UserID
	u.SessionKey = ""
	u.TwitterAccessToken = gothUser.AccessToken
	u.TwitterAvatarURL = gothUser.AvatarURL
	u.Name = gothUser.Name
	return u
}

func GetUserBooks(userID string) []Book {
	s := session.Copy()
	defer s.Close()
	booksCollection := s.DB(dbname).C("books")
	var books []Book
	if err := booksCollection.Find(bson.M{"owner": userID}).All(&books); err != nil {
	}
	return books
}

func GetAllBooks() []Book {
	s := session.Copy()
	defer s.Close()
	booksCollection := s.DB(dbname).C("books")
	var books []Book
	if err := booksCollection.Find(bson.M{}).All(&books); err != nil {
	}
	return books
}

func GetBook(bookID string) (Book, error) {
	s := session.Copy()
	defer s.Close()
	booksCollection := s.DB(dbname).C("books")
	var book Book
	err := booksCollection.Find(bson.M{"_id": bson.ObjectIdHex(bookID)}).One(&book)
	return book, err
}

func GetUser(userID string) (User, error) {
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB(dbname).C("users")
	var user User
	err := usersCollection.Find(bson.M{"twitterid": userID}).One(&user)
	return user, err
}

func mainHandler(c echo.Context) error {
	data := H{"user": c.Get("user"), "books": GetAllBooks()}
	return c.Render(200, "index", data)
}

func deleteBookHandler(c echo.Context) error {
	user := c.Get("user").(User)
	bookID := c.Param("id")
	s := session.Copy()
	defer s.Close()
	booksCollection := s.DB(dbname).C("books")
	tradesCollection := s.DB(dbname).C("trades")
	if err := booksCollection.Remove(bson.M{"_id": bson.ObjectIdHex(bookID), "owner": user.TwitterID}); err != nil {
		return c.String(400, "You can only delete your own books")
	}
	tradesCollection.Remove(bson.M{"book1id": bson.ObjectIdHex(bookID)})
	tradesCollection.Remove(bson.M{"book2id": bson.ObjectIdHex(bookID)})
	return c.Redirect(303, "/mybooks")
}

func myBooksHandler(c echo.Context) error {
	user := c.Get("user").(User)
	data := H{"user": user, "books": GetUserBooks(user.TwitterID)}
	return c.Render(200, "my-books", data)
}

func newBookHandler(c echo.Context) error {
	user := c.Get("user").(User)
	q := strings.Trim(c.FormValue("q"), " \n\r\t")
	data := H{"user": user, "q": q}
	if q == "" {
		data["error"] = "You must enter a name"
		data["books"] = GetUserBooks(user.TwitterID)
		return c.Render(200, "my-books", data)
	}
	client := http.Client{}
	svc, _ := books.New(&client)
	volumes, _ := svc.Volumes.List(q).Do()
	if volumes.TotalItems == 0 {
		data["error"] = "Cannot find this book"
		data["books"] = GetUserBooks(user.TwitterID)
		return c.Render(200, "my-books", data)
	}
	s := session.Copy()
	defer s.Close()
	booksCollection := s.DB(dbname).C("books")
	volume := volumes.Items[0]
	newBook := Book{}
	newBook.ID = bson.NewObjectId()
	newBook.ApiID = volume.Id
	newBook.SmallThumbnail = volume.VolumeInfo.ImageLinks.SmallThumbnail
	newBook.Title = volume.VolumeInfo.Title
	newBook.Owner = user.TwitterID
	var book Book
	if err := booksCollection.Find(bson.M{"apiid": newBook.ApiID, "owner": user.TwitterID}).One(&book); err == nil {
		data["error"] = "You already have this book in your collection"
		data["books"] = GetUserBooks(user.TwitterID)
		return c.Render(200, "my-books", data)
	}
	if err := booksCollection.Insert(newBook); err != nil {
		fmt.Println("Unable to insert book", err)
		return err
	}
	return c.Redirect(302, "/mybooks")
}

func accountHandler(c echo.Context) error {
	user := c.Get("user").(User)
	data := H{"user": user}
	return c.Render(200, "account", data)
}

func editAccountHandler(c echo.Context) error {
	user := c.Get("user").(User)
	data := H{"user": user}
	return c.Render(200, "edit-account", data)
}

func editAccountSubmitHandler(c echo.Context) error {
	user := c.Get("user").(User)
	name := c.FormValue("name")
	city := c.FormValue("city")
	state := c.FormValue("state")
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB(dbname).C("users")
	if err := usersCollection.Update(bson.M{"twitterid": user.TwitterID}, bson.M{"$set": bson.M{"name": name, "city": city, "state": state}}); err != nil {
		fmt.Println("unable to edit profile", err)
		return err
	}
	return c.Redirect(303, "/account")
}

func newTradeHandler(c echo.Context) error {
	user := c.Get("user").(User)
	bookID := c.Param("bookID")
	book, err := GetBook(bookID)
	if err != nil {
		return c.Redirect(302, "/")
	}
	// You cannot trade your own book to yourself
	if book.Owner == user.TwitterID {
		c.Redirect(302, "/")
	}
	owner, err := GetUser(book.Owner)
	if err != nil {
		fmt.Println(err)
		c.String(500, "owner not found")
	}
	myBooks := GetUserBooks(user.TwitterID)
	data := H{"user": user, "book": book, "owner": owner, "mybooks": myBooks, "selectedBook": ""}
	return c.Render(200, "new-trade", data)
}

func createTradeHandler(c echo.Context) error {
	user := c.Get("user").(User)
	wantedBookID := c.FormValue("wantedbook")
	bookOwnerID := c.FormValue("bookowner")
	myBookID := c.FormValue("mybook")
	s := session.Copy()
	defer s.Close()
	tradesCollection := s.DB(dbname).C("trades")
	booksCollection := s.DB(dbname).C("books")
	var book Book
	if err := booksCollection.Find(bson.M{"_id": bson.ObjectIdHex(wantedBookID)}).One(&book); err != nil {
		return c.String(400, "Wanted book not found")
	}
	if !bson.IsObjectIdHex(myBookID) {
		owner, _ := GetUser(bookOwnerID)
		myBooks := GetUserBooks(user.TwitterID)
		data := H{"user": user, "book": book, "owner": owner, "mybooks": myBooks, "selectedBook": ""}
		data["error"] = "You have to select a book to exchange"
		return c.Render(200, "new-trade", data)
	}
	if book.Owner != bookOwnerID {
		return c.String(400, "Book changed owner")
	}
	var myBook Book
	if err := booksCollection.Find(bson.M{"_id": bson.ObjectIdHex(myBookID), "owner": user.TwitterID}).One(&myBook); err != nil {
		return c.String(400, "Looks like the book you want to trade is not yours")
	}
	if err := tradesCollection.Find(bson.M{"book1id": myBook.ID, "book2id": book.ID}).One(&Book{}); err == nil {
		owner, _ := GetUser(bookOwnerID)
		myBooks := GetUserBooks(user.TwitterID)
		data := H{"user": user, "book": book, "owner": owner, "mybooks": myBooks, "selectedBook": myBookID}
		data["error"] = "You already asked to trade these two books"
		return c.Render(200, "new-trade", data)
	}
	if err := tradesCollection.Find(bson.M{"book2id": myBook.ID, "book1id": book.ID}).One(&Book{}); err == nil {
		owner, _ := GetUser(bookOwnerID)
		myBooks := GetUserBooks(user.TwitterID)
		data := H{"user": user, "book": book, "owner": owner, "mybooks": myBooks, "selectedBook": myBookID}
		data["error"] = "he owner already asked you to trade these two books"
		return c.Render(200, "new-trade", data)
	}
	trade := Trade{}
	trade.ID = bson.NewObjectId()
	trade.User1ID = user.TwitterID
	trade.User2ID = bookOwnerID
	trade.Book1ID = myBook.ID
	trade.Book2ID = book.ID
	trade.Book1Title = myBook.Title
	trade.Book1Thumbnail = myBook.SmallThumbnail
	trade.Book2Title = book.Title
	trade.Book2Thumbnail = book.SmallThumbnail
	if err := tradesCollection.Insert(trade); err != nil {
		fmt.Println(err)
		return c.String(500, "Unable to create trade")
	}
	return c.Redirect(303, "/mytrades")
}

func myTradesHandler(c echo.Context) error {
	user := c.Get("user").(User)
	s := session.Copy()
	defer s.Close()
	tradesCollection := s.DB(dbname).C("trades")
	var myTrades []Trade
	if err := tradesCollection.Find(bson.M{"user1id": user.TwitterID}).All(&myTrades); err != nil {
	}
	var requestedTrades []Trade
	if err := tradesCollection.Find(bson.M{"user2id": user.TwitterID}).All(&requestedTrades); err != nil {
	}
	data := H{"user": user, "mytrades": myTrades, "requestedtrades": requestedTrades}
	return c.Render(200, "my-trades", data)
}

func deleteTradeHandler(c echo.Context) error {
	user := c.Get("user").(User)
	tradeID := c.Param("tradeID")
	s := session.Copy()
	defer s.Close()
	tradesCollection := s.DB(dbname).C("trades")
	if err := tradesCollection.Remove(bson.M{"_id": bson.ObjectIdHex(tradeID), "user1id": user.TwitterID}); err != nil {
		return c.String(401, "You can only delete your trades")
	}
	return c.Redirect(303, "/mytrades")
}

func declineTradeHandler(c echo.Context) error {
	user := c.Get("user").(User)
	tradeID := c.Param("tradeID")
	s := session.Copy()
	defer s.Close()
	tradesCollection := s.DB(dbname).C("trades")
	if err := tradesCollection.Remove(bson.M{"_id": bson.ObjectIdHex(tradeID), "user2id": user.TwitterID}); err != nil {
		return c.String(401, "You can only decline trade requested to you")
	}
	return c.Redirect(303, "/mytrades")
}

func acceptTradeHandler(c echo.Context) error {
	user := c.Get("user").(User)
	tradeID := c.Param("tradeID")
	s := session.Copy()
	defer s.Close()
	tradesCollection := s.DB(dbname).C("trades")
	booksCollection := s.DB(dbname).C("books")

	// Get trade
	var trade Trade
	if err := tradesCollection.Find(bson.M{"_id": bson.ObjectIdHex(tradeID), "user2id": user.TwitterID}).One(&trade); err != nil {
		return c.String(400, "You can only accept trades offered to you")
	}

	// Remove trades including these books
	tradesCollection.Remove(bson.M{"book1id": trade.Book2ID})
	tradesCollection.Remove(bson.M{"book1id": trade.Book1ID})
	tradesCollection.Remove(bson.M{"book2id": trade.Book2ID})
	tradesCollection.Remove(bson.M{"book2id": trade.Book1ID})

	// Switch books ownership
	if err := booksCollection.Update(bson.M{"_id": trade.Book1ID}, bson.M{"$set": bson.M{"owner": trade.User2ID}}); err != nil {
		return c.String(500, "Something went wrong")
	}
	if err := booksCollection.Update(bson.M{"_id": trade.Book2ID}, bson.M{"$set": bson.M{"owner": trade.User1ID}}); err != nil {
		return c.String(500, "Something went wrong")
	}

	return c.Redirect(303, "/mybooks")
}

func GenerateToken() string {
	// This error can safely be ignored.
	// Only crash when year is outside of [0,9999]
	key, _ := time.Now().MarshalText()
	token := hex.EncodeToString(hmac.New(sha256.New, key).Sum(nil))
	return token
}

func SetUserAuthToken(gothUser goth.User, token string) error {
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB(dbname).C("users")
	if err := usersCollection.Update(bson.M{"twitterid": gothUser.UserID}, bson.M{"$set": bson.M{"sessionkey": token}}); err != nil {
		u := NewUserFromGothUser(gothUser)
		u.SessionKey = token
		if err := usersCollection.Insert(*u); err != nil {
			if !mgo.IsDup(err) {
				return err
			}
		}
	}
	return nil
}

func authTwitterHandler(c echo.Context) error {
	// try to get the user without re-authenticating
	res := c.Response()
	req := c.Request()
	if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
		token := GenerateToken()
		if err := SetUserAuthToken(gothUser, token); err != nil {
			return err
		}
		cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
		c.SetCookie(&cookie)
		return c.Redirect(303, "/")
	} else {
		gothic.BeginAuthHandler(res, req)
		return nil
	}
}

func authTwitterCallbackHandler(c echo.Context) error {
	gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return err
	}
	token := GenerateToken()
	if err := SetUserAuthToken(gothUser, token); err != nil {
		return err
	}
	cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(303, "/")
}

func logoutHandler(c echo.Context) error {
	//cookie1 := &http.Cookie{
	//  Name:   fmt.Sprintf("twitter%s", gothic.SessionName),
	//  Value:  "",
	//  Path:   "/",
	//  MaxAge: -1,
	//}
	//c.SetCookie(&cookie1)
	cookie := http.Cookie{Name: authTokenCookieName, Value: "", Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(302, "/")
}

func ensureIndex() {
	s := session.Copy()
	defer s.Close()
	c := s.DB(dbname).C("users")
	index := mgo.Index{
		Key:        []string{"twitterid"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		panic(err)
	}
}

// IsAuthMiddleware will ensure user is authenticated.
// - Find user from context
// - If user is empty, redirect to home
func IsAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(User)
		if user.TwitterID == "" {
			return c.Redirect(302, "/")
		}
		return next(c)
	}
}

// SetUserMiddleware Get user and put it into echo context.
// - Get auth-token from cookie
// - If exists, get user from database
// - If found, set user in echo context
// - Otherwise, empty user will be put in context
func SetUserMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user User
		authCookie, err := c.Cookie(authTokenCookieName)
		if err != nil {
			c.Set("user", user)
			return next(c)
		}
		s := session.Copy()
		defer s.Close()
		usersCollection := s.DB(dbname).C("users")
		if err := usersCollection.Find(bson.M{"sessionkey": authCookie.Value}).One(&user); err != nil {
		}
		c.Set("user", user)
		return next(c)
	}
}

func getProvider(req *http.Request) (string, error) {
	return "twitter", nil
}

func start(c *cli.Context) error {
	goth.UseProviders(
		twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), os.Getenv("TWITTER_CALLBACK")),
	)
	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	gothic.GetProviderName = getProvider

	dbname = os.Getenv("MONGODB_DBNAME")
	var err error
	session, err = mgo.Dial(os.Getenv("MONGODB_URI"))
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	ensureIndex()

	t := &Template{}
	port := c.Int("port")
	e := echo.New()
	e.Static("/public", "public")
	e.Use(SetUserMiddleware)
	e.Renderer = t
	e.Debug = true
	e.Logger.SetLevel(log.INFO)
	e.GET("/", mainHandler)
	e.GET("/auth/twitter", authTwitterHandler)
	e.GET("/auth/twitter/callback", authTwitterCallbackHandler)
	e.GET("/logout", logoutHandler)

	needAuthGroup := e.Group("")
	needAuthGroup.Use(IsAuthMiddleware)
	needAuthGroup.GET("/account", accountHandler)
	needAuthGroup.GET("/account/edit", editAccountHandler)
	needAuthGroup.POST("/account/edit/submit", editAccountSubmitHandler)
	needAuthGroup.GET("/mybooks", myBooksHandler)
	needAuthGroup.GET("/mybooks/delete/:id", deleteBookHandler)
	needAuthGroup.POST("/newbook", newBookHandler)
	needAuthGroup.GET("/trades/new/:bookID", newTradeHandler)
	needAuthGroup.POST("/trades/new", createTradeHandler)
	needAuthGroup.GET("/mytrades", myTradesHandler)
	needAuthGroup.GET("/trades/delete/:tradeID", deleteTradeHandler)
	needAuthGroup.GET("/trades/decline/:tradeID", declineTradeHandler)
	needAuthGroup.GET("/trades/accept/:tradeID", acceptTradeHandler)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
	return nil
}

func main() {
	app := cli.NewApp()
	app.Author = "Alain Gilbert"
	app.Email = "alain.gilbert.15@gmail.com"
	app.Name = "FCC books app"
	app.Usage = "FCC books app"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:   "port",
			Value:  3001,
			Usage:  "Webserver port",
			EnvVar: "PORT",
		},
	}
	app.Action = start
	app.Run(os.Args)
}
