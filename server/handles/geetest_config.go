package handles

const (
	GEETEST_ID                = "d3609d46ab4e839376e00fd8d5e62b12"
	GEETEST_KEY               = "f09e22ec58789020eb3288df34f225c6"
	REDIS_SERVER              = "127.0.0.1:6379"                                 // 对bypass状态进行缓存的redis服务地址
	BYPASS_URL                = "http://bypass.geetest.com/v1/bypass_status.php" // 向geetest发送获取bypass状态请求的url
	CYCLE_TIME                = 10                                               // 轮询发送获取bypass状态请求的时间间隔(单位为秒)
	GEETEST_BYPASS_STATUS_KEY = "gt_server_bypass_status"                        // bypass状态存入redis时使用的key值
)
