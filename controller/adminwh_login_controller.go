package controller

import (
	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/Uchel/auth-test2/model"
	"github.com/Uchel/auth-test2/usecase"

	"github.com/gin-gonic/gin"
)

type AuthAdminWhLoginController struct {
	AdminLoginUsecase usecase.AdminWhLoginUsecase
	waktu             int
	secret            string
}

func (c *AuthAdminWhLoginController) LoginAdmin(ctx *gin.Context) {

	var loginReq model.LoginReq

	if err := ctx.BindJSON(&loginReq); err != nil {
		ctx.JSON(http.StatusBadRequest, "invalid input")
		return
	}
	email, password := c.AdminLoginUsecase.FindByEmailAdminWh(loginReq.Email)

	// authenticate user (compare username dan password)
	expire := time.Now().Add(time.Minute * time.Duration(c.waktu))
	if loginReq.Email == email && loginReq.Password == password {
		// generate JWT token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["email"] = loginReq.Email
		claims["role"] = "wh"
		claims["exp"] = expire.Unix()

		tokenString, err := token.SignedString([]byte(c.secret))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "gagal generate token"})
			return
		}

		ctx.SetSameSite(http.SameSiteLaxMode)
		ctx.SetCookie("Authorization", tokenString, expire.Minute(), "/", "localhost", false, true)
	} else {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unregistered user"})
	}
}

func (c *AuthAdminWhLoginController) LogoutWh(ctx *gin.Context) {
	expire := time.Now().Add(time.Minute * time.Duration(c.waktu))
	ctx.SetCookie("Authorization", "", -expire.Minute(), "/", "", false, true)

	ctx.JSON(http.StatusOK, gin.H{"message": "Logout berhasil"})
}
func NewAdminLoginController(u usecase.AdminWhLoginUsecase, waktu int, secret string) *AuthAdminWhLoginController {
	controller := AuthAdminWhLoginController{

		AdminLoginUsecase: u,
		waktu:             waktu,
		secret:            secret,
	}

	return &controller
}
