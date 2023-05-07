package controller

import (
	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/Uchel/auth-test/model"
	"github.com/Uchel/auth-test/usecase"

	"github.com/gin-gonic/gin"
)

type AuthIcTeamLoginController struct {
	IcTeamLoginUsecase usecase.IcTeamLoginUsecase
	waktu              int
	secret             string
}

func (c *AuthIcTeamLoginController) LoginIcTeam(ctx *gin.Context) {

	var loginReq model.LoginReq

	if err := ctx.BindJSON(&loginReq); err != nil {
		ctx.JSON(http.StatusBadRequest, "invalid input")
		return
	}
	email, password := c.IcTeamLoginUsecase.FindByEmailIc(loginReq.Email)

	// authenticate user (compare username dan password)

	expire := time.Now().Add(time.Minute * time.Duration(c.waktu))
	if loginReq.Email == email && loginReq.Password == password {
		// generate JWT token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["email"] = loginReq.Email
		claims["role"] = "ic"
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
func (c *AuthIcTeamLoginController) LogoutIc(ctx *gin.Context) {
	expire := time.Now().Add(time.Minute * time.Duration(c.waktu))
	ctx.SetCookie("Authorization", "", -expire.Minute(), "/", "", false, true)

	ctx.JSON(http.StatusOK, gin.H{"message": "Logout berhasil"})
}

func NewIcTeamLoginController(u usecase.IcTeamLoginUsecase, waktu int, secret string) *AuthIcTeamLoginController {
	controller := AuthIcTeamLoginController{

		IcTeamLoginUsecase: u,
		waktu:              waktu,
		secret:             secret,
	}

	return &controller
}
