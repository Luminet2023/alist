package handles

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Xhofe/go-cache"
	"github.com/alist-org/alist/v3/internal/conf"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/op"
	"github.com/alist-org/alist/v3/internal/setting"
	"github.com/alist-org/alist/v3/server/common"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/pquerna/otp/totp"
)

//	type cjson struct {
//		Captcha_id     string `json:"captcha_id"`
//		Captcha_output string `json:"captcha_output"`
//		Lot_number     string `json:"lot_number" `
//		Pass_token     string `json:"pass_token" `
//		Gen_time       string `json:"gen_time" `
//		Username       string `json:"username" `
//		Password       string `json:"password"`
//		OtpCode        string `json:"otp_code"`
//	}
type captcha struct {
	Captcha_output string `json:"captcha_output"`
	Lot_number     string `json:"lot_number" `
	Pass_token     string `json:"pass_token"`
	Gen_time       string `json:"gen_time" `
	Username       string `json:"username" `
	Password       string `json:"password"`
	OtpCode        string `json:"otp_code"`
}
type UserData struct {
	Username string `json:"username"`
	Password string `json:"password"`
	OtpCode  string `json:"otp_code"`
}

var loginCache = cache.NewMemCache[int]()
var (
	defaultDuration = time.Minute * 5
	defaultTimes    = 6
)
var cli = http.Client{Timeout: time.Second * 5}

const API_SERVER string = "http://gcaptcha4.geetest.com"

type GlobalVars struct {
	ExampleVar string
}

// geetest 验证接口
// geetest verification interface

var ip string

func GeetestCaptcha(c *gin.Context) {
	if setting.GetStr(conf.GeetestON) == "enabled" {
		CAPTCHA_ID := setting.GetStr(conf.GeetestID)
		const GEETESTCaptchaVerifyUrl = "http://gcaptcha4.geetest.com/validate"
		CAPTCHA_KEY := setting.GetStr(conf.GeetestKey)
		// c.JSON(http.StatusOK, gin.H{
		// 	"id":  CAPTCHA_ID,
		// 	"key": CAPTCHA_KEY,
		// })
		count, ok := loginCache.Get(ip)
		if ok && count >= defaultTimes {
			var cjson captcha
			if err := c.ShouldBindBodyWith(&cjson, binding.JSON); err != nil {
				// 处理错误，这里可以根据具体需求进行处理
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
				return
			}
			// c.JSON(http.StatusOK, gin.H{
			// 	"gin": cjson,
			// })

			var lot_number = cjson.Lot_number
			var captcha_output = cjson.Captcha_output
			var pass_token = cjson.Pass_token
			var gen_time = cjson.Gen_time

			sign_token := hmac_encode(CAPTCHA_KEY, lot_number)
			// c.JSON(http.StatusOK, gin.H{
			// 	"lot_number":     lot_number,
			// 	"pass_token":     pass_token,
			// 	"captcha_output": captcha_output,
			// 	"gen_time":       gen_time,
			// 	"sign_token":     sign_token,
			// })
			// 向极验转发前端数据 + “sign_token” 签名
			// send front end parameter + "sign_token" signature to geetest
			form_data := make(url.Values)
			form_data["sign_token"] = []string{sign_token}
			form_data["lot_number"] = []string{lot_number}
			form_data["captcha_output"] = []string{captcha_output}
			form_data["pass_token"] = []string{pass_token}
			form_data["gen_time"] = []string{gen_time}
			form_data["sign_token"] = []string{hmac_encode(CAPTCHA_KEY, lot_number)}

			cli := http.Client{Timeout: time.Second * 5}
			resp, err := cli.PostForm(fmt.Sprintf("%s?captcha_id=%s", GEETESTCaptchaVerifyUrl, CAPTCHA_ID), form_data)

			if err != nil || resp.StatusCode != 200 {
				err = errors.New("肥鸡验证失败")
				common.ErrorResp(c, err, 400)
			}

			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)

			type captchaResponse struct {
				Result string `json:"result"`
				Reason string `json:"reason"`
			}

			captchaResp := &captchaResponse{}

			err = json.Unmarshal(body, captchaResp)
			if err != nil {
				// 处理解析JSON的错误，这里可以根据具体需求进行处理
				err = errors.New("肥鸡验证失败")
				common.ErrorResp(c, err, 400)
			}
			if captchaResp.Result == "success" {
				LoginHash(c)
			} else {
				err = errors.New("肥鸡验证失败")
				common.ErrorResp(c, err, 400)
			}
			loginCache.Expire(ip, defaultDuration)
		} else {
			LoginHash(c)
		}
	} else {
		LoginHash(c)
	}

}

// hmac-sha256 加密：  CAPTCHA_KEY,lot_number
// hmac-sha256 encrypt: CAPTCHA_KEY, lot_number
func hmac_encode(key string, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

type LoginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password"`
	OtpCode  string `json:"otp_code"`
}

// Login Deprecated
func Login(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	req.Password = model.StaticHash(req.Password)
	loginHash(c, &req)
}

// LoginHash login with password hashed by sha256
func LoginHash(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		common.ErrorResp(c, err, 300)
		return
	}
	loginHash(c, &req)
}

func loginHash(c *gin.Context, req *LoginReq) {
	// check username
	count, _ := loginCache.Get(ip) // 忽略第二个返回值
	user, err := op.GetUserByName(req.Username)
	if err != nil {
		common.ErrorResp(c, err, 400)
		loginCache.Set(ip, count+1)
		return
	}
	// validate password hash
	if err := user.ValidatePwdStaticHash(req.Password); err != nil {
		common.ErrorResp(c, err, 400)
		loginCache.Set(ip, count+1)
		return
	}
	// check 2FA
	if user.OtpSecret != "" {
		if !totp.Validate(req.OtpCode, user.OtpSecret) {
			loginCache.Set(ip, count+1)
			return
		}
	}
	// generate token
	token, err := common.GenerateToken(user)
	if err != nil {
		common.ErrorResp(c, err, 400, true)
		return
	}
	common.SuccessResp(c, gin.H{"token": token})
	loginCache.Del(ip)
}

type UserResp struct {
	model.User
	Otp bool `json:"otp"`
}

// CurrentUser get current user by token
// if token is empty, return guest user
func CurrentUser(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	userResp := UserResp{
		User: *user,
	}
	userResp.Password = ""
	if userResp.OtpSecret != "" {
		userResp.Otp = true
	}
	common.SuccessResp(c, userResp)
}

func UpdateCurrent(c *gin.Context) {
	var req model.User
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	user.Username = req.Username
	if req.Password != "" {
		user.SetPassword(req.Password)
	}
	user.SsoID = req.SsoID
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}

func Generate2FA(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, "Guest user can not generate 2FA code", 403)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Alist",
		AccountName: user.Username,
	})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	img, err := key.Image(400, 400)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	// to base64
	var buf bytes.Buffer
	png.Encode(&buf, img)
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	common.SuccessResp(c, gin.H{
		"qr":     "data:image/png;base64," + b64,
		"secret": key.Secret(),
	})
}

type Verify2FAReq struct {
	Code   string `json:"code" binding:"required"`
	Secret string `json:"secret" binding:"required"`
}

func Verify2FA(c *gin.Context) {
	var req Verify2FAReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, "Guest user can not generate 2FA code", 403)
		return
	}
	if !totp.Validate(req.Code, req.Secret) {
		common.ErrorStrResp(c, "Invalid 2FA code", 400)
		return
	}
	user.OtpSecret = req.Secret
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}
func NeedCaptcha(c *gin.Context) {
	if setting.GetStr(conf.GeetestON) == "enabled" {
		count, ok := loginCache.Get(ip)
		CAPTCHA_ID := setting.GetStr(conf.GeetestID)
		if ok && count >= defaultTimes {
			response := map[string]interface{}{
				"code":         200,
				"need_captcha": ok && count >= defaultTimes,
				"captchaId":    CAPTCHA_ID,
				"msg":          "success",
			}
			c.JSON(http.StatusOK, response)
			loginCache.Expire(ip, defaultDuration)
		} else {
			c.String(http.StatusOK, `{"code":200,"need_captcha":false,"msg":"success"}`)
		}
	} else {
		c.String(http.StatusOK, `{"code":200,"need_captcha":false,"msg":"success"}`)
	}
}
