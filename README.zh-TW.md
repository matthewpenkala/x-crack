# 『安全開發教程』年輕人的第一款弱口令掃描器(x-crack)

## 用法

    x-crack scan -i iplist.txt -u user.txt -p pass.txt -t 15

    [0000]  INFO xsec crack: checking ip active
    Checking progress:  [100.00%] [5/5]
    [0000]  INFO xsec crack: Ip: x.x.x.211, Port: 22, Protocol: [SSH], Username: admin, Password: admin
    [0000]  INFO xsec crack: Ip: x.x.x.9, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.56, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.236, Port: 22, Protocol: [SSH], Username: admin, Password: 123456
    [0001]  INFO xsec crack: Ip: x.x.x.134, Port: 22, Protocol: [SSH], Username: admin, Password: 123456

## 概述

我們在做企業安全時，弱口令檢測是系統/網絡安全的最基礎的部分之一，根據經驗，經常會出現弱口令的服務如下：

-   FTP
-   SSH
-   中小企業
-   MYSQL
-   微軟SQL
-   PostgreSQL 後
-   雷迪斯
-   蒙古數據庫
-   彈性搜索

那咱們就一起用GO來寫一款常見服務的弱口令掃描器，且支持以插件的形式增加新的服務掃描模塊。我們的教程暫定為只掃以上服務。

給掃描器啟一個屌炸天的名字`x-crack`，在$GOPATH/src/中建立一個x-crack項目後開始擼碼，不要給我說什麼底層原理、框架內核，老夫敲代碼就是一把梭。

開發完畢的項目地址為：[HTTPS://GitHub.com/net像fly/小-crack](https://github.com/netxfly/x-crack)

## 開工

### 數據結構定義

-   掃描模塊的輸入內容為為IP、端口及協議的列表，我們需要定義一個IpAddr的數據結構；
-   每個服務的每次掃描需要傳入的參數為IP、端口、協議、用戶名和密碼，需要定義一個Service結構來包括這些內容；
-   每條Service的記錄在掃描模塊進行嘗試後，會得出掃描結果成功與否，我們再定義一個ScanResult數據結構。

按照開發規範，數據結構的定義統一放到models目錄中，全部的數據結構定義如下：

```go

package models

type Service struct {
	Ip       string
	Port     int
	Protocol string
	Username string
	Password string
}

type ScanResult struct {
	Service Service
	Result  bool
}

type IpAddr struct {
	Ip       string
	Port     int
	Protocol string
}
```

### FTP掃描模塊

go語言有現成的FTP模塊，我們找一個star數最多的直接`go get`安裝一下即可使用了：

```bash
go get -u github.com/jlaffaye/ftp
```

我們把所有的掃描模塊放到`plugins`目錄中，FTP協議的掃描插件如下所示：

```go

package plugins

import (
	"github.com/jlaffaye/ftp"

	"x-crack/models"
	"x-crack/vars"


	"fmt"
)

func ScanFtp(s models.Service) (err error, result models.ScanResult) {
	result.Service = s
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", s.Ip, s.Port), vars.TimeOut)
	if err == nil {
		err = conn.Login(s.Username, s.Password)
		if err == nil {
			defer conn.Logout()
			result.Result = true
		}
	}
	return err, result
}
```

每個連接需要設置超時時間，防止因網絡問題導致的阻塞，我們打算通過程序的命令行來控制超時時間，所以定義了一個全局變量TimeOut。
放在vars模塊中的原因是防止放在這個模塊中後會和其他模塊互相調用導致的循環import

寫代碼雖然可以一把梭，但是不能等著洋洋灑灑地把幾萬行都寫完再運行，比如我們的目標是造一輛豪車，不能等著所有零件設計好，都裝上去再發動車測試，正確的開發流程是把寫邊測，不要等輪子造出來，而是在螺絲、齒輪階段就測試。

以下為FTP掃描插件這個齒輪的測試代碼及結果。

```go
package plugins_test

import (
	"x-crack/models"
	"x-crack/plugins"

	"testing"
)

func TestScanFtp(t *testing.T) {
	s := models.Service{Ip: "127.0.0.1", Port: 21, Protocol: "ftp", Username: "ftp", Password: "ftp"}
	t.Log(plugins.ScanFtp(s))
}
```

測試結果滿足預期，說明我們這個零件不是次品，可以繼續再造其他零件了。

```bash
$ go test -v plugins/ftp_test.go
=== RUN   TestScanFtp
--- PASS: TestScanFtp (0.00s)
	ftp_test.go:36: dial tcp 127.0.0.1:21: getsockopt: connection refused {{127.0.0.1 21 ftp ftp ftp} false}
PASS
ok  	command-line-arguments	0.025s
```

### SSH掃描模塊

go的標準庫中自帶了ssh包，直接調用即可，完整代碼如下：

```go

package plugins

import (
	"golang.org/x/crypto/ssh"

	"x-crack/models"
	"x-crack/vars"

	"fmt"
	"net"
)

func ScanSsh(s models.Service) (err error, result models.ScanResult) {
	result.Service = s
	config := &ssh.ClientConfig{
		User: s.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.Password),
		},
		Timeout: vars.TimeOut,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", s.Ip, s.Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo xsec")
		if err == nil && errRet == nil {
			defer session.Close()
			result.Result = true
		}
	}
	return err, result
}
 
```

同樣，每個子模塊寫好後都需要先用go test跑一下看是否滿足預期，測試代碼如下：

```go

package plugins_test

import (
	"x-crack/models"
	"x-crack/plugins"

	"testing"
)

func TestScanSsh(t *testing.T) {
	s := models.Service{Ip: "127.0.0.1", Port: 22, Username: "root", Password: "123456", Protocol: "ssh"}
	t.Log(plugins.ScanSsh(s))
} 
```

測試結果如下：

```go
$ go test -v plugins/ssh_test.go
=== RUN   TestScanSsh
--- PASS: TestScanSsh (0.00s)
	ssh_test.go:36: dial tcp 127.0.0.1:22: getsockopt: connection refused {{127.0.0.1 22 ssh root 123456} false}
PASS
ok  	command-line-arguments	0.026s
```

### SMB掃描模塊

SMB弱口令的掃描插件，我們使用了`github.com/stacktitan/smb/smb`包，同樣直接`go get`安裝一下即可拿來使用。
代碼如下：

```go

package plugins

import (
	"github.com/stacktitan/smb/smb"

	"x-crack/models"
)

func ScanSmb(s models.Service) (err error, result models.ScanResult) {
	result.Service = s
	options := smb.Options{
		Host:        s.Ip,
		Port:        s.Port,
		User:        s.Username,
		Password:    s.Password,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			result.Result = true
		}
	}
	return err, result
}

```

同樣也先寫測試用例來測試一下，測試代碼如下：

```go
package plugins_test

import (
	"x-crack/models"
	"x-crack/plugins"

	"testing"
)

func TestScanSmb(t *testing.T) {
	s := models.Service{Ip: "share.xsec.io", Port: 445, Protocol: "smb", Username: "xsec", Password: "fsafffdsfdsa"}
	t.Log(plugins.ScanSmb(s))
}
```

測試結果：

```bash
hartnett at hartnettdeMacBook-Pro in /data/code/golang/src/x-crack (master)
$ go test -v plugins/smb_test.go
=== RUN   TestScanSmb
--- PASS: TestScanSmb (0.04s)
	smb_test.go:36: NT Status Error: Logon failed
		 {{share.xsec.io 445 smb xsec fsafffdsfdsa} false}
PASS
ok  	command-line-arguments	0.069s
```

### MYSQL、MSSQL和POSTGRESQL掃描模塊

MYSQL、MSSQL和POSTGRESQL的掃描模塊，我使用了第三方的ORM`xorm`，當然也可以直接使用原生的sql driver來實現，我們這裡圖方便用`xorm`一把梭了。
對於`xorm`來說，這3個掃描插件的實現方法大同小異，為了節約篇幅，咱們只看mysql掃描插件的實現，其他2個插件可以參考github中的完整源碼。
首先還是先`go get`要用到的包:

```bash
go get github.com/netxfly/mysql
go get github.com/go-xorm/xorm
github.com/go-xorm/core
```

接下來我們把需要驗證的IP、port、username、password組成datasource傳遞給xorm，完整代碼如下：

```go
package plugins

import (
	_ "github.com/netxfly/mysql"
	"github.com/go-xorm/xorm"
	"github.com/go-xorm/core"

	"x-crack/models"

	"fmt"
)

func ScanMysql(service models.Service) (err error, result models.ScanResult) {
	result.Service = service

	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8", service.Username,
		service.Password, service.Ip, service.Port, "mysql")
	Engine, err := xorm.NewEngine("mysql", dataSourceName)

	if err == nil {
		Engine.SetLogLevel(core.LOG_OFF)
		// fix "[mysql] packets.go:33: unexpected EOF" error
		Engine.SetMaxIdleConns(0)
		// Engine.SetConnMaxLifetime(time.Second * 30)
		defer Engine.Close()
		err = Engine.Ping()
		if err == nil {
			result.Result = true
		}
	}
	return err, result
}
```

眼尖的同學也許發現了，上面`github.com/netxfly/mysql`這個mysql包是放在筆者的github下的，這是為什麼呢？

因為直接用mysql這個包的話，在掃描的過程中會遇到`[mysql] packets.go:33: unexpected EOF" error`的異常輸出，影響了我們程序在掃描過程中輸出UI的美觀性，這對於帥氣的我是無法接受的，通過設置參數的方法無法解決，最後只好直接fork了一份mysql的包，把打印這個異常的語句註釋掉再提交上去直接使用了。

測試代碼：

```go

package plugins_test

import (
	"testing"

	"x-crack/plugins"
	"x-crack/models"
)

func TestScanMysql(t *testing.T) {
	service := models.Service{Ip: "10.10.10.10", Port: 3306, Protocol: "mysql", Username: "root", Password: "123456"}
	t.Log(plugins.ScanMysql(service))
}
```

測試結果：

```bash
go test -v plugins/mysql_test.go
=== RUN   TestScanMysql
--- PASS: TestScanMysql (0.02s)
	mysql_test.go:36: Error 1045: Access denied for user 'root'@'10.10.10.100' (using password: YES) {{10.10.10.10 3306 mysql root 123456} false}
PASS
ok  	command-line-arguments	0.041s
```

### Redis掃描模塊

`go get`安裝第三方包`github.com/go-redis/redis`，完整代碼如下：

```go

package plugins

import (
	"github.com/go-redis/redis"

	"x-crack/models"
	"x-crack/vars"

	"fmt"
)

func ScanRedis(s models.Service) (err error, result models.ScanResult) {
	result.Service = s
	opt := redis.Options{Addr: fmt.Sprintf("%v:%v", s.Ip, s.Port),
		Password: s.Password, DB: 0, DialTimeout: vars.TimeOut}
	client := redis.NewClient(&opt)
	defer client.Close()
	_, err = client.Ping().Result()
	if err == nil {
		result.Result = true
	}
	return err, result
}

```

測試代碼：

```go

package plugins_test

import (
	"x-crack/models"
	"x-crack/plugins"

	"testing"
)

func TestScanRedis(t *testing.T) {
	s := models.Service{Ip: "127.0.0.1", Port: 6379, Password: "test"}
	t.Log(plugins.ScanRedis(s))
}
```

測試結果：

```bash
go test -v plugins/redis_test.go
=== RUN   TestScanRedis
--- PASS: TestScanRedis (0.00s)
	redis_test.go:36: dial tcp 127.0.0.1:6379: getsockopt: connection refused {{127.0.0.1 6379   test} false}
PASS
ok  	command-line-arguments	0.025s
```

### MONGODB掃描模塊

mongodb掃描模塊依賴mgo包，可用`go get`合令直接安裝。

```bash
go get gopkg.in/mgo.v2
```

完整代碼：

```go

package plugins

import (
	"gopkg.in/mgo.v2"

	"x-crack/models"
	"x-crack/vars"

	"fmt"
)

func ScanMongodb(s models.Service) (err error, result models.ScanResult) {
	result.Service = s
	url := fmt.Sprintf("mongodb://%v:%v@%v:%v/%v", s.Username, s.Password, s.Ip, s.Port, "test")
	session, err := mgo.DialWithTimeout(url, vars.TimeOut)

	if err == nil {
		defer session.Close()
		err = session.Ping()
		if err == nil {
			result.Result = true
		}
	}

	return err, result
}
```

測試結果：

```bash
go test -v plugins/mongodb_test.go
=== RUN   TestScanMongodb
--- PASS: TestScanMongodb (3.53s)
	mongodb_test.go:36: no reachable servers {{127.0.0.1 27017 mongodb test test} false}
PASS
ok  	command-line-arguments	3.558s
```

### ELASTICSEARCH掃描模塊

ELASTICSEARCH掃描插件依賴第三方包`gopkg.in/olivere/elastic.v3`，同樣也是直接`go get`安裝。
完整代碼如下：

```go
package plugins

import (
	"gopkg.in/olivere/elastic.v3"

	"x-crack/models"
	
	"fmt"
)

func ScanElastic(s models.Service) (err error, result models.ScanResult) {
	result.Service = s
	client, err := elastic.NewClient(elastic.SetURL(fmt.Sprintf("http://%v:%v", s.Ip, s.Port)),
		elastic.SetMaxRetries(3),
		elastic.SetBasicAuth(s.Username, s.Password),
	)
	if err == nil {
		_, _, err = client.Ping(fmt.Sprintf("http://%v:%v", s.Ip, s.Port)).Do()
		if err == nil {
			result.Result = true
		}
	}
	return err, result
}

```

測試代碼：

```go
package plugins_test

import (
	"x-crack/models"
	"x-crack/plugins"

	"testing"
)

func TestScanElastic(t *testing.T) {
	s := models.Service{Ip: "127.0.0.1", Port: 9200, Protocol: "elastic", Username: "root", Password: "123456"}
	t.Log(plugins.ScanElastic(s))
}

```

測試結果如下：

```bash
go test -v plugins/elastic_test.go
=== RUN   TestScanElastic
--- PASS: TestScanElastic (5.02s)
	elastic_test.go:36: no Elasticsearch node available {{127.0.0.1 9200 elastic root 123456} false}
PASS
ok  	command-line-arguments	5.061s
```

### 掃描模塊插件化

前面我們寫好的掃描插件的函數原始是一致，我們可以將這組函數放到一個map中，在掃描的過程中自動化根據不同的協議調用不同的掃描插件。

以後新加的掃描插件，可以按這種方法直接註冊。

```go

package plugins

import (
	"x-crack/models"
)

type ScanFunc func(service models.Service) (err error, result models.ScanResult)

var (
	ScanFuncMap map[string]ScanFunc
)

func init() {
	ScanFuncMap = make(map[string]ScanFunc)
	ScanFuncMap["FTP"] = ScanFtp
	ScanFuncMap["SSH"] = ScanSsh
	ScanFuncMap["SMB"] = ScanSmb
	ScanFuncMap["MSSQL"] = ScanMssql
	ScanFuncMap["MYSQL"] = ScanMysql
	ScanFuncMap["POSTGRESQL"] = ScanPostgres
	ScanFuncMap["REDIS"] = ScanRedis
	ScanFuncMap["ELASTICSEARCH"] = ScanElastic
	ScanFuncMap["MONGODB"] = ScanMongodb
}

```

## 掃描任務調度

前面我們寫好了一些常見服務的弱口令掃描插件，也測試通過了。
接下來我們需要實現從命令行參數傳遞iplist、用戶名字典和密碼字典進去，並讀取相應的信息進行掃描調度的功能，細分一下，需要做以下幾件事：

-   讀取iplist列表
-   讀取用戶名字典
-   讀取密碼字典
-   生成掃描任務
-   掃描任務調度
-   掃描任務執行
-   掃描結果保存
-   命令行調用外殼

### 讀取ip\\用戶名和密碼字典

該模塊主要用了標準庫中的`bufio`包，逐行讀取文件，進行過濾後直接生成相應的slice。其中iplist支持以下格式：

```bash
127.0.0.1:3306|mysql
8.8.8.8:22
9.9.9.9:6379
108.61.223.105:2222|ssh
```

對於標準的端口，程序可以自動判斷其協議，對於非標準端口的協議，需要在後面加一個字段標註一下協議。

為了防止咱們的程序被腳本小子們濫用，老夫就不提供端口掃描、協議識別等功能了，安全工程師們可以把自己公司的端口掃描器產出的結果丟到這個里面來掃。

```go

package util

import (
	"x-crack/models"
	"x-crack/logger"
	"x-crack/vars"

	"os"
	"bufio"
	"strings"
	"strconv"
)

func ReadIpList(fileName string) (ipList []models.IpAddr) {
	ipListFile, err := os.Open(fileName)
	if err != nil {
		logger.Log.Fatalf("Open ip List file err, %v", err)
	}

	defer ipListFile.Close()

	scanner := bufio.NewScanner(ipListFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		ipPort := strings.TrimSpace(scanner.Text())
		t := strings.Split(ipPort, ":")
		ip := t[0]
		portProtocol := t[1]
		tmpPort := strings.Split(portProtocol, "|")
		// ip列表中指定了端口对应的服务
		if len(tmpPort) == 2 {
			port, _ := strconv.Atoi(tmpPort[0])
			protocol := strings.ToUpper(tmpPort[1])
			if vars.SupportProtocols[protocol] {
				addr := models.IpAddr{Ip: ip, Port: port, Protocol: protocol}
				ipList = append(ipList, addr)
			} else {
				logger.Log.Infof("Not support %v, ignore: %v:%v", protocol, ip, port)
			}
		} else {
			// 通过端口查服务
			port, err := strconv.Atoi(tmpPort[0])
			if err == nil {
				protocol, ok := vars.PortNames[port]
				if ok && vars.SupportProtocols[protocol] {
					addr := models.IpAddr{Ip: ip, Port: port, Protocol: protocol}
					ipList = append(ipList, addr)
				}
			}
		}

	}

	return ipList
}

func ReadUserDict(userDict string) (users []string, err error) {
	file, err := os.Open(userDict)
	if err != nil {
		logger.Log.Fatalf("Open user dict file err, %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		user := strings.TrimSpace(scanner.Text())
		if user != "" {
			users = append(users, user)
		}
	}
	return users, err
}

func ReadPasswordDict(passDict string) (password []string, err error) {
	file, err := os.Open(passDict)
	if err != nil {
		logger.Log.Fatalf("Open password dict file err, %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		passwd := strings.TrimSpace(scanner.Text())
		if passwd != "" {
			password = append(password, passwd)
		}
	}
	password = append(password, "")
	return password, err
}

```

IP列表、用戶名字典與密碼字典讀取的測試代碼：

```go

package util_test

import (
	"x-crack/util"

	"testing"
)

func TestReadIpList(t *testing.T) {
	ipList := "/tmp/iplist.txt"
	t.Log(util.ReadIpList(ipList))
}

func TestReadUserDict(t *testing.T) {
	userDict := "/tmp/user.dic"
	t.Log(util.ReadUserDict(userDict))
}

func TestReadPasswordDict(t *testing.T) {
	passDict := "/tmp/pass.dic"
	t.Log(util.ReadPasswordDict(passDict))
}

```

這個模塊的測試結果如下：

```bash
go test -v util/file_test.go
=== RUN   TestReadIpList
--- PASS: TestReadIpList (0.00s)
	file_test.go:35: [{127.0.0.1 3306 MYSQL} {8.8.8.8 22 SSH} {9.9.9.9 6379 REDIS} {108.61.223.105 2222 SSH}]
=== RUN   TestReadUserDict
--- PASS: TestReadUserDict (0.00s)
	file_test.go:40: [root admin test guest info adm mysql user administrator ftp sa] <nil>
=== RUN   TestReadPasswordDict
--- PASS: TestReadPasswordDict (0.00s)
	file_test.go:45: [1314520520 135246 135246789 135792468 1357924680 147258369 1472583690 1qaz2wsx 5201314 54321 55555 654321 789456123 88888 888888 88888888 987654321 9876543210 ^%$#@~! a123123 a123456 a12345678 a123456789 aa123456 aa123456789 aaa123456 aaaaa aaaaaa aaaaaaaa abc123 abc123456 abc123456789 abcd123 abcd1234 abcd123456 admin admin888 ] <nil>
PASS
ok  	command-line-arguments	0.022s
```

其中iplist在加載的過程中不是無腦全部讀進去的，在正式掃描前會先過濾一次，把不通的ip和端口對剔除掉，以免影響掃描效率，代碼如下：

```go

package util

import (
	"gopkg.in/cheggaaa/pb.v2"

	"x-crack/models"
	"x-crack/logger"
	"x-crack/vars"

	"net"
	"sync"
	"fmt"
)

var (
	AliveAddr []models.IpAddr
	mutex     sync.Mutex
)

func init() {
	AliveAddr = make([]models.IpAddr, 0)
}

func CheckAlive(ipList []models.IpAddr) ([]models.IpAddr) {
	logger.Log.Infoln("checking ip active")
	
	var wg sync.WaitGroup
	wg.Add(len(ipList))

	for _, addr := range ipList {
		go func(addr models.IpAddr) {
			defer wg.Done()
			SaveAddr(check(addr))
		}(addr)
	}
	wg.Wait()
	vars.ProcessBarActive.Finish()

	return AliveAddr
}

func check(ipAddr models.IpAddr) (bool, models.IpAddr) {
	alive := false
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ipAddr.Ip, ipAddr.Port), vars.TimeOut)
	if err == nil {
		alive = true
	}
	vars.ProcessBarActive.Increment()
	return alive, ipAddr
}

func SaveAddr(alive bool, ipAddr models.IpAddr) {
	if alive {
		mutex.Lock()
		AliveAddr = append(AliveAddr, ipAddr)
		mutex.Unlock()
	}
}

```

通過標準端口查詢對應服務的功能在vars包中定義了，為了避免多個包之間的循環導入，我們把所有的全局變量都集中到了一個獨立的vars包中。

`PortNames`map為標準端口對應的服務，在加了新的掃描插件後，也需要更新這個map的內容。

```go

package vars

import (
	"github.com/patrickmn/go-cache"

	"gopkg.in/cheggaaa/pb.v2"

	"sync"
	"time"
	"strings"
)

var (
	IpList     = "iplist.txt"
	ResultFile = "x_crack.txt"

	UserDict = "user.dic"
	PassDict = "pass.dic"

	TimeOut = 3 * time.Second
	ScanNum = 5000

	DebugMode bool

	StartTime time.Time

	ProgressBar      *pb.ProgressBar
	ProcessBarActive *pb.ProgressBar
)

var (
	CacheService *cache.Cache
	Mutex        sync.Mutex

	PortNames = map[int]string{
		21:    "FTP",
		22:    "SSH",
		445:   "SMB",
		1433:  "MSSQL",
		3306:  "MYSQL",
		5432:  "POSTGRESQL",
		6379:  "REDIS",
		9200:  "ELASTICSEARCH",
		27017: "MONGODB",
	}

	// 标记特定服务的特定用户是否破解成功，成功的话不再尝试破解该用户
	SuccessHash map[string]bool

	SupportProtocols map[string]bool
)

func init() {
	SuccessHash = make(map[string]bool)
	CacheService = cache.New(cache.NoExpiration, cache.DefaultExpiration)

	SupportProtocols = make(map[string]bool)
	for _, proto := range PortNames {
		SupportProtocols[strings.ToUpper(proto)] = true
	}

}

```

### 任務調度

任務調度模塊包含了生成掃描任務，按指定的協程數分發和執行掃描任務的功能。

```go

package util

import (
	"github.com/sirupsen/logrus"

	"gopkg.in/cheggaaa/pb.v2"

	"x-crack/models"
	"x-crack/logger"
	"x-crack/vars"
	"x-crack/util/hash"
	"x-crack/plugins"

	"sync"
	"strings"
	"fmt"
	"time"
)

func GenerateTask(ipList []models.IpAddr, users []string, passwords []string) (tasks []models.Service, taskNum int) {
	tasks = make([]models.Service, 0)

	for _, user := range users {
		for _, password := range passwords {
			for _, addr := range ipList {
				service := models.Service{Ip: addr.Ip, Port: addr.Port, Protocol: addr.Protocol, Username: user, Password: password}
				tasks = append(tasks, service)
			}
		}
	}

	return tasks, len(tasks)
}

func DistributionTask(tasks []models.Service) () {
	totalTask := len(tasks)
	scanBatch := totalTask / vars.ScanNum
	logger.Log.Infoln("Start to scan")
	
	for i := 0; i < scanBatch; i++ {
		curTasks := tasks[vars.ScanNum*i:vars.ScanNum*(i+1)]
		ExecuteTask(curTasks)
	}

	if totalTask%vars.ScanNum > 0 {
		lastTask := tasks[vars.ScanNum*scanBatch:totalTask]
		ExecuteTask(lastTask)
	}

	models.SavaResultToFile()
	models.ResultTotal()
	models.DumpToFile(vars.ResultFile)
}

func ExecuteTask(tasks []models.Service) () {
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for _, task := range tasks {
		if vars.DebugMode {
			logger.Log.Debugf("checking: Ip: %v, Port: %v, [%v], UserName: %v, Password: %v", task.Ip, task.Port,
				task.Protocol, task.Username, task.Password)
		}

		var k string
		protocol := strings.ToUpper(task.Protocol)

		if protocol == "REDIS" || protocol == "FTP" {
			k = fmt.Sprintf("%v-%v-%v", task.Ip, task.Port, task.Protocol)
		} else {
			k = fmt.Sprintf("%v-%v-%v", task.Ip, task.Port, task.Username)
		}

		h := hash.MakeTaskHash(k)
		if hash.CheckTashHash(h) {
			wg.Done()
			continue
		}

		go func(task models.Service, protocol string) {
			defer wg.Done()
			fn := plugins.ScanFuncMap[protocol]
			models.SaveResult(fn(task))
		}(task, protocol)

		vars.ProgressBar.Increment()
	}
	waitTimeout(&wg, vars.TimeOut)
}

```

個別掃描插件沒有指定超時時間的功能，所以我們額外為所有的掃描插件都提供了一個超時函數，防止個別協程被阻塞，影響了掃描器整體的速度。

```go
// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

```

任務調度模塊的測試代碼如下：

```go

package util_test

import (
	"x-crack/util"

	"testing"
)

func TestGenerateTask(t *testing.T) {
	ipList := "/tmp/iplist.txt"
	userDic := "/tmp/user.dic"
	passDic := "/tmp/pass.dic"

	users, _ := util.ReadUserDict(userDic)
	passwords, _ := util.ReadPasswordDict(passDic)

	t.Log(util.GenerateTask(util.ReadIpList(ipList), users, passwords))
}

func TestDistributionTask(t *testing.T) {
	ipList := "/tmp/iplist.txt"
	userDic := "/tmp/user.dic"
	passDic := "/tmp/pass.dic"

	users, _ := util.ReadUserDict(userDic)
	passwords, _ := util.ReadPasswordDict(passDic)

	tasks, _ := util.GenerateTask(util.ReadIpList(ipList), users, passwords)
	util.DistributionTask(tasks)
}

```

測試結果如下：

```bash
$ go test -v util/task_test.go
=== RUN   TestGenerateTask
--- PASS: TestGenerateTask (0.00s)
	task_test.go:41: [{127.0.0.1 3306 MYSQL root admin} {8.8.8.8 22 SSH root admin} {9.9.9.9 6379 REDIS root admin} {108.61.223.105 2222 SSH root admin} {127.0.0.1 3306 MYSQL root admin888} {8.8.8.8 22 SSH root admin888} {9.9.9.9 6379 REDIS root admin888} {108.61.223.105 2222 SSH root admin888} {127.0.0.1 3306 MYSQL root 123456} {8.8.8.8 22 SSH root 123456} {9.9.9.9 6379 REDIS root 123456} {108.61.223.105 2222 SSH root 123456} {127.0.0.1 3306 MYSQL root } {8.8.8.8 22 SSH root } {9.9.9.9 6379 REDIS root } {108.61.223.105 2222 SSH root } {127.0.0.1 3306 MYSQL admin admin} {8.8.8.8 22 SSH admin admin} {9.9.9.9 6379 REDIS admin admin} {108.61.223.105 2222 SSH admin admin} {127.0.0.1 3306 MYSQL admin admin888} {8.8.8.8 22 SSH admin admin888} {9.9.9.9 6379 REDIS admin admin888} {108.61.223.105 2222 SSH admin admin888} {127.0.0.1 3306 MYSQL admin 123456} {8.8.8.8 22 SSH admin 123456} {9.9.9.9 6379 REDIS admin 123456} {108.61.223.105 2222 SSH admin 123456} {127.0.0.1 3306 MYSQL admin } {8.8.8.8 22 SSH admin } {9.9.9.9 6379 REDIS admin } {108.61.223.105 2222 SSH admin } {127.0.0.1 3306 MYSQL test admin} {8.8.8.8 22 SSH test admin} {9.9.9.9 6379 REDIS test admin} {108.61.223.105 2222 SSH test admin} {127.0.0.1 3306 MYSQL test admin888} {8.8.8.8 22 SSH test admin888} {9.9.9.9 6379 REDIS test admin888} {108.61.223.105 2222 SSH test admin888} {127.0.0.1 3306 MYSQL test 123456} {8.8.8.8 22 SSH test 123456} {9.9.9.9 6379 REDIS test 123456} {108.61.223.105 2222 SSH test 123456} {127.0.0.1 3306 MYSQL test } {8.8.8.8 22 SSH test } {9.9.9.9 6379 REDIS test } {108.61.223.105 2222 SSH test } {127.0.0.1 3306 MYSQL guest admin} {8.8.8.8 22 SSH guest admin} {9.9.9.9 6379 REDIS guest admin} {108.61.223.105 2222 SSH guest admin} {127.0.0.1 3306 MYSQL guest admin888} {8.8.8.8 22 SSH guest admin888} {9.9.9.9 6379 REDIS guest admin888} {108.61.223.105 2222 SSH guest admin888} {127.0.0.1 3306 MYSQL guest 123456} {8.8.8.8 22 SSH guest 123456} {9.9.9.9 6379 REDIS guest 123456} {108.61.223.105 2222 SSH guest 123456} {127.0.0.1 3306 MYSQL guest } {8.8.8.8 22 SSH guest } {9.9.9.9 6379 REDIS guest } {108.61.223.105 2222 SSH guest } {127.0.0.1 3306 MYSQL info admin} {8.8.8.8 22 SSH info admin} {9.9.9.9 6379 REDIS info admin} {108.61.223.105 2222 SSH info admin} {127.0.0.1 3306 MYSQL info admin888} {8.8.8.8 22 SSH info admin888} {9.9.9.9 6379 REDIS info admin888} {108.61.223.105 2222 SSH info admin888} {127.0.0.1 3306 MYSQL info 123456} {8.8.8.8 22 SSH info 123456} {9.9.9.9 6379 REDIS info 123456} {108.61.223.105 2222 SSH info 123456} {127.0.0.1 3306 MYSQL info } {8.8.8.8 22 SSH info } {9.9.9.9 6379 REDIS info } {108.61.223.105 2222 SSH info } {127.0.0.1 3306 MYSQL adm admin} {8.8.8.8 22 SSH adm admin} {9.9.9.9 6379 REDIS adm admin} {108.61.223.105 2222 SSH adm admin} {127.0.0.1 3306 MYSQL adm admin888} {8.8.8.8 22 SSH adm admin888} {9.9.9.9 6379 REDIS adm admin888} {108.61.223.105 2222 SSH adm admin888} {127.0.0.1 3306 MYSQL adm 123456} {8.8.8.8 22 SSH adm 123456} {9.9.9.9 6379 REDIS adm 123456} {108.61.223.105 2222 SSH adm 123456} {127.0.0.1 3306 MYSQL adm } {8.8.8.8 22 SSH adm } {9.9.9.9 6379 REDIS adm } {108.61.223.105 2222 SSH adm } {127.0.0.1 3306 MYSQL mysql admin} {8.8.8.8 22 SSH mysql admin} {9.9.9.9 6379 REDIS mysql admin} {108.61.223.105 2222 SSH mysql admin} {127.0.0.1 3306 MYSQL mysql admin888} {8.8.8.8 22 SSH mysql admin888} {9.9.9.9 6379 REDIS mysql admin888} {108.61.223.105 2222 SSH mysql admin888} {127.0.0.1 3306 MYSQL mysql 123456} {8.8.8.8 22 SSH mysql 123456} {9.9.9.9 6379 REDIS mysql 123456} {108.61.223.105 2222 SSH mysql 123456} {127.0.0.1 3306 MYSQL mysql } {8.8.8.8 22 SSH mysql } {9.9.9.9 6379 REDIS mysql } {108.61.223.105 2222 SSH mysql } {127.0.0.1 3306 MYSQL user admin} {8.8.8.8 22 SSH user admin} {9.9.9.9 6379 REDIS user admin} {108.61.223.105 2222 SSH user admin} {127.0.0.1 3306 MYSQL user admin888} {8.8.8.8 22 SSH user admin888} {9.9.9.9 6379 REDIS user admin888} {108.61.223.105 2222 SSH user admin888} {127.0.0.1 3306 MYSQL user 123456} {8.8.8.8 22 SSH user 123456} {9.9.9.9 6379 REDIS user 123456} {108.61.223.105 2222 SSH user 123456} {127.0.0.1 3306 MYSQL user } {8.8.8.8 22 SSH user } {9.9.9.9 6379 REDIS user } {108.61.223.105 2222 SSH user } {127.0.0.1 3306 MYSQL administrator admin} {8.8.8.8 22 SSH administrator admin} {9.9.9.9 6379 REDIS administrator admin} {108.61.223.105 2222 SSH administrator admin} {127.0.0.1 3306 MYSQL administrator admin888} {8.8.8.8 22 SSH administrator admin888} {9.9.9.9 6379 REDIS administrator admin888} {108.61.223.105 2222 SSH administrator admin888} {127.0.0.1 3306 MYSQL administrator 123456} {8.8.8.8 22 SSH administrator 123456} {9.9.9.9 6379 REDIS administrator 123456} {108.61.223.105 2222 SSH administrator 123456} {127.0.0.1 3306 MYSQL administrator } {8.8.8.8 22 SSH administrator } {9.9.9.9 6379 REDIS administrator } {108.61.223.105 2222 SSH administrator } {127.0.0.1 3306 MYSQL ftp admin} {8.8.8.8 22 SSH ftp admin} {9.9.9.9 6379 REDIS ftp admin} {108.61.223.105 2222 SSH ftp admin} {127.0.0.1 3306 MYSQL ftp admin888} {8.8.8.8 22 SSH ftp admin888} {9.9.9.9 6379 REDIS ftp admin888} {108.61.223.105 2222 SSH ftp admin888} {127.0.0.1 3306 MYSQL ftp 123456} {8.8.8.8 22 SSH ftp 123456} {9.9.9.9 6379 REDIS ftp 123456} {108.61.223.105 2222 SSH ftp 123456} {127.0.0.1 3306 MYSQL ftp } {8.8.8.8 22 SSH ftp } {9.9.9.9 6379 REDIS ftp } {108.61.223.105 2222 SSH ftp } {127.0.0.1 3306 MYSQL sa admin} {8.8.8.8 22 SSH sa admin} {9.9.9.9 6379 REDIS sa admin} {108.61.223.105 2222 SSH sa admin} {127.0.0.1 3306 MYSQL sa admin888} {8.8.8.8 22 SSH sa admin888} {9.9.9.9 6379 REDIS sa admin888} {108.61.223.105 2222 SSH sa admin888} {127.0.0.1 3306 MYSQL sa 123456} {8.8.8.8 22 SSH sa 123456} {9.9.9.9 6379 REDIS sa 123456} {108.61.223.105 2222 SSH sa 123456} {127.0.0.1 3306 MYSQL sa } {8.8.8.8 22 SSH sa } {9.9.9.9 6379 REDIS sa } {108.61.223.105 2222 SSH sa }] 176
=== RUN   TestDistributionTask
[0000]  INFO xsec crack: Start to scan
[0003]  INFO xsec crack: Finshed scan, total result: 0, used time: 2562047h47m16.854775807s
--- PASS: TestDistributionTask (3.01s)
PASS
ok  	command-line-arguments	3.035s
```

到此為止，我們的掃描器的核心部件已經造好了，接下來需要給掃描器上個高上大的命令行調用的外殼就大功造成了。

### 命令行模塊

命令行控制模塊，我們單獨定義了一個cmd包，依賴第三方包`github.com/urfave/cli`。

我們在cmd模塊中定義了掃描和掃描結果導出為txt文件2個命令及一系統全局選項。

```go

package cmd

import (
	"github.com/urfave/cli"

	"x-crack/util"
	"x-crack/models"
)

var Scan = cli.Command{
	Name:        "scan",
	Usage:       "start to crack weak password",
	Description: "start to crack weak password",
	Action:      util.Scan,
	Flags: []cli.Flag{
		boolFlag("debug, d", "debug mode"),
		intFlag("timeout, t", 5, "timeout"),
		intFlag("scan_num, n", 5000, "thread num"),
		stringFlag("ip_list, i", "iplist.txt", "iplist"),
		stringFlag("user_dict, u", "user.dic", "user dict"),
		stringFlag("pass_dict, p", "pass.dic", "password dict"),
	},
}

var Dump = cli.Command{
	Name:        "dump",
	Usage:       "dump result to a text file",
	Description: "dump result to a text file",
	Action:      models.Dump,
	Flags: []cli.Flag{
		stringFlag("outfile, o", "x_crack.txt", "scan result file"),
	},
}

func stringFlag(name, value, usage string) cli.StringFlag {
	return cli.StringFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}

func boolFlag(name, usage string) cli.BoolFlag {
	return cli.BoolFlag{
		Name:  name,
		Usage: usage,
	}
}

func intFlag(name string, value int, usage string) cli.IntFlag {
	return cli.IntFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}

```

然後再回到`x-crack/util`包為我們的scan command模塊專門寫一個Action，如下：

```go

func Scan(ctx *cli.Context) (err error) {
	if ctx.IsSet("debug") {
		vars.DebugMode = ctx.Bool("debug")
	}

	if vars.DebugMode {
		logger.Log.Level = logrus.DebugLevel
	}

	if ctx.IsSet("timeout") {
		vars.TimeOut = time.Duration(ctx.Int("timeout")) * time.Second
	}

	if ctx.IsSet("scan_num") {
		vars.ScanNum = ctx.Int("scan_num")
	}

	if ctx.IsSet("ip_list") {
		vars.IpList = ctx.String("ip_list")
	}

	if ctx.IsSet("user_dict") {
		vars.UserDict = ctx.String("user_dict")
	}

	if ctx.IsSet("pass_dict") {
		vars.PassDict = ctx.String("pass_dict")
	}

	if ctx.IsSet("outfile") {
		vars.ResultFile = ctx.String("outfile")
	}

	vars.StartTime = time.Now()

	userDict, uErr := ReadUserDict(vars.UserDict)
	passDict, pErr := ReadPasswordDict(vars.PassDict)
	ipList := ReadIpList(vars.IpList)
	aliveIpList := CheckAlive(ipList)
	if uErr == nil && pErr == nil {
		tasks, _ := GenerateTask(aliveIpList, userDict, passDict)
		DistributionTask(tasks)
	}
	return err
}

```

然後再到`x-crack/models`中為dump命令寫一個Action，如下：

```go

package models

import (
	"github.com/patrickmn/go-cache"
	"github.com/urfave/cli"

	"x-crack/vars"
	"x-crack/logger"
	"x-crack/util/hash"

	"encoding/gob"
	"time"
	"fmt"
	"os"
	"strings"
)

func init() {
	gob.Register(Service{})
	gob.Register(ScanResult{})
}

func SaveResult(err error, result ScanResult) {
	if err == nil && result.Result {
		var k string
		protocol := strings.ToUpper(result.Service.Protocol)

		if protocol == "REDIS" || protocol == "FTP" {
			k = fmt.Sprintf("%v-%v-%v", result.Service.Ip, result.Service.Port, result.Service.Protocol)
		} else {
			k = fmt.Sprintf("%v-%v-%v", result.Service.Ip, result.Service.Port, result.Service.Username)
		}

		h := hash.MakeTaskHash(k)
		hash.SetTaskHask(h)

		_, found := vars.CacheService.Get(k)
		if !found {
			logger.Log.Infof("Ip: %v, Port: %v, Protocol: [%v], Username: %v, Password: %v", result.Service.Ip,
				result.Service.Port, result.Service.Protocol, result.Service.Username, result.Service.Password)
		}
		vars.CacheService.Set(k, result, cache.NoExpiration)
	}
}

func SavaResultToFile() (error) {
	return vars.CacheService.SaveFile("x_crack.db")
}

func CacheStatus() (count int, items map[string]cache.Item) {
	count = vars.CacheService.ItemCount()
	items = vars.CacheService.Items()
	return count, items
}

func ResultTotal() {
	vars.ProgressBar.Finish()
	logger.Log.Info(fmt.Sprintf("Finshed scan, total result: %v, used time: %v",
		vars.CacheService.ItemCount(),
		time.Since(vars.StartTime)))
}

func LoadResultFromFile() {
	vars.CacheService.LoadFile("x_crack.db")
	vars.ProgressBar.Finish()
	logger.Log.Info(fmt.Sprintf("Finshed scan, total result: %v", vars.CacheService.ItemCount()))
}

func Dump(ctx *cli.Context) (err error) {
	LoadResultFromFile()

	err = DumpToFile(vars.ResultFile)
	if err != nil {
		logger.Log.Fatalf("Dump result to file err, Err: %v", err)
	}
	return err
}

func DumpToFile(filename string) (err error) {
	file, err := os.Create(filename)
	if err == nil {
		_, items := CacheStatus()
		for _, v := range items {
			result := v.Object.(ScanResult)
			file.WriteString(fmt.Sprintf("%v:%v|%v,%v:%v\n", result.Service.Ip, result.Service.Port,
				result.Service.Protocol, result.Service.Username, result.Service.Password))
		}
	}
	return err
}

```

最後給IP\\port過濾與任務掃描模塊加上一個騷氣的進度條，我們的掃描器就算大功告成了。

`x-crack/util/util.go`的代碼片段：

```go

func CheckAlive(ipList []models.IpAddr) ([]models.IpAddr) {
	logger.Log.Infoln("checking ip active")
	vars.ProcessBarActive = pb.StartNew(len(ipList))
	vars.ProcessBarActive.SetTemplate(`{{ rndcolor "Checking progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor}}  {{rtime . | rndcolor }}`)
....
```

`x-crack/util/task.go`的代碼片斷：

```go
func DistributionTask(tasks []models.Service) () {
	totalTask := len(tasks)
	scanBatch := totalTask / vars.ScanNum
	logger.Log.Infoln("Start to scan")
	vars.ProgressBar = pb.StartNew(totalTask)
	vars.ProgressBar.SetTemplate(`{{ rndcolor "Scanning progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor }} {{rtime . | rndcolor}} `)
...
```

掃描器代碼中還有些細節沒有在教程中詳細說，有興趣的同學可以思考下以下問題，然後再結合代碼看看老夫的實現方式：

1.  掃到一個弱口令後，如何取消相同IP\\port和用戶名請求，避免掃描效率低下
2.  對於FTP匿名訪問，如何只記錄一個密碼，而不是把所有用戶名都記錄下來
3.  對於Redis這種沒有用戶名的服務，如何只記錄一次密碼，而不是記錄所有的所有用戶及正常的密碼的組合
4.  對於不支持設置超時的掃描插件，如何統一設置超時時間

## 掃描器測試

到現在為止，我們的掃描器已經大功告成了，可以編譯出來運行一下看看效果了。以下腳本可一鍵同時編譯出mac、linux和Windows平台的可執行文件（筆者的開發環境為MAC）

```bash
#!/bin/bash

go build x-crack.go
mv x-crack x-crack_darwin_amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build x-crack.go
mv x-crack x-crack_linux_amd64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build x-crack.go
mv x-crack.exe x-crack_windows_amd64.exe
go build x-crack.go
```

### 使用參數

```bash
hartnett at hartnettdeMacBook-Pro in /data/code/golang/src/x-crack (master)
$ ./x-crack
NAME:
   x-crack - Weak password scanner, Support: FTP/SSH/MSSQL/MYSQL/PostGreSQL/REDIS/ElasticSearch/MONGODB

USAGE:
   x-crack [global options] command [command options] [arguments...]

VERSION:
   20171227

AUTHOR(S):
   netxfly <x@xsec.io>

COMMANDS:
     scan     start to crack weak password
     dump     dump result to a text file
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d                  debug mode
   --timeout value, -t value    timeout (default: 5)
   --scan_num value, -n value   thread num (default: 5000)
   --ip_list value, -i value    iplist (default: "iplist.txt")
   --user_dict value, -u value  user dict (default: "user.dic")
   --pass_dict value, -p value  password dict (default: "pass.dic")
   --outfile value, -o value    scan result file (default: "x_crack.txt")
   --help, -h                   show help
   --version, -v                print the version
```

### 使用截圖

![](https://docs.xsec.io/images/x-crack/x-crack001.png)

![](https://docs.xsec.io/images/x-crack/x-crack002.png)
