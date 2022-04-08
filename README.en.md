# "Security Development Tutorial" The first weak password scanner (x-crack) for young people

## usage

    x-crack scan -i iplist.txt -u user.txt -p pass.txt -t 15

    [0000]  INFO xsec crack: checking ip active
    Checking progress:  [100.00%] [5/5]
    [0000]  INFO xsec crack: Ip: x.x.x.211, Port: 22, Protocol: [SSH], Username: admin, Password: admin
    [0000]  INFO xsec crack: Ip: x.x.x.9, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.56, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.236, Port: 22, Protocol: [SSH], Username: admin, Password: 123456
    [0001]  INFO xsec crack: Ip: x.x.x.134, Port: 22, Protocol: [SSH], Username: admin, Password: 123456

## Overview

When we are doing enterprise security, weak password detection is one of the most basic parts of system/network security. According to experience, services with weak passwords often appear as follows:

-   FTP
-   SSH
-   SMB
-   MYSQL
-   MSSQL
-   POSTGRESQL
-   REDIS
-   MONGODB
-   ELASTICSEARCH

Then let's use GO to write a weak password scanner for common services, and support adding new service scanning modules in the form of plug-ins. Our tutorial is tentatively scheduled to only scan the above services.

Give the scanner a crazy name`x-crack`, After creating an x-crack project in $GOPATH/src/, start coding. Don't tell me about the underlying principles and framework kernels. The old man is just a shuttle when it comes to coding.

The address of the completed project is:<https://github.com/netxfly/x-crack>

## start

### data structure definition

-   The input content of the scanning module is a list of IP, port and protocol, we need to define a data structure of IpAddr;
-   The parameters that need to be passed in each scan of each service are IP, port, protocol, user name and password, and a Service structure needs to be defined to include these contents;
-   After each service record is tried by the scanning module, the scanning result will be obtained or not, and we will define a ScanResult data structure.

According to the development specification, the definition of the data structure is uniformly placed in the models directory, and all the data structures are defined as follows:

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

### FTP scanning module

The go language has a ready-made FTP module, we find the one with the largest number of stars directly`go get`Just install it and use it:

```bash
go get -u github.com/jlaffaye/ftp
```

We put all scan modules in`plugins`In the directory, the scanning plugin for the FTP protocol is as follows:

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

Each connection needs to set a timeout period to prevent blocking due to network problems. We intend to control the timeout period through the command line of the program, so a global variable TimeOut is defined.
The reason for placing it in the vars module is to prevent circular imports from calling each other with other modules after being placed in this module.

Although it is possible to write code in a short time, we cannot wait for tens of thousands of lines to be written and then run. For example, our goal is to build a luxury car, we cannot wait for all the parts to be designed and installed before starting the car test. , The correct development process is to test while writing, not to wait for the wheel to be built, but to test at the stage of screws and gears.

The following is the test code and result of the gear of the FTP scanning plugin.

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

The test results meet the expectations, indicating that our part is not a defective product, and we can continue to remanufacture other parts.

```bash
$ go test -v plugins/ftp_test.go
=== RUN   TestScanFtp
--- PASS: TestScanFtp (0.00s)
	ftp_test.go:36: dial tcp 127.0.0.1:21: getsockopt: connection refused {{127.0.0.1 21 ftp ftp ftp} false}
PASS
ok  	command-line-arguments	0.025s
```

### SSH scanning module

The standard library of go comes with the ssh package, which can be called directly. The complete code is as follows:

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

Similarly, after each submodule is written, you need to run go test to see if it meets the expectations. The test code is as follows:

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

The test results are as follows:

```go
$ go test -v plugins/ssh_test.go
=== RUN   TestScanSsh
--- PASS: TestScanSsh (0.00s)
	ssh_test.go:36: dial tcp 127.0.0.1:22: getsockopt: connection refused {{127.0.0.1 22 ssh root 123456} false}
PASS
ok  	command-line-arguments	0.026s
```

### SMB scan module

SMB weak password scanning plugin, we used`github.com/stacktitan/smb/smb`package, the same directly`go get`Just install it and use it.
code show as below:

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

Also write a test case to test it first. The test code is as follows:

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

Test Results:

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

### MYSQL, MSSQL and POSTGRESQL scan modules

Scanning modules for MYSQL, MSSQL and POSTGRESQL, I use a third-party ORM`xorm`, of course, it can also be implemented directly by using the native sql driver, which is convenient for us to use here.`xorm`A shuttle.
for`xorm`For example, the implementation methods of these three scanning plug-ins are similar. In order to save space, we only look at the implementation of the mysql scanning plug-in. For the other two plug-ins, you can refer to the complete source code in github.
first or first`go get`Packages to use:

```bash
go get github.com/netxfly/mysql
go get github.com/go-xorm/xorm
github.com/go-xorm/core
```

Next, we pass the IP, port, username, and password to be verified as a datasource to xorm. The complete code is as follows:

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

Sharp-eyed classmates may have noticed, above`github.com/netxfly/mysql`This mysql package is placed under the author's github, why is this?

Because if you use the mysql package directly, you will encounter`[mysql] packets.go:33: unexpected EOF" error`The abnormal output of , affects the aesthetics of the output UI of our program during the scanning process. This is unacceptable to the handsome me. It cannot be solved by setting parameters. In the end, I had to directly fork a mysql package and print this The abnormal statement is commented out and then submitted for direct use.

Test code:

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

Test Results:

```bash
go test -v plugins/mysql_test.go
=== RUN   TestScanMysql
--- PASS: TestScanMysql (0.02s)
	mysql_test.go:36: Error 1045: Access denied for user 'root'@'10.10.10.100' (using password: YES) {{10.10.10.10 3306 mysql root 123456} false}
PASS
ok  	command-line-arguments	0.041s
```

### Redis scan module

`go get`Install third-party packages`github.com/go-redis/redis`, the complete code is as follows:

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

Test code:

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

Test Results:

```bash
go test -v plugins/redis_test.go
=== RUN   TestScanRedis
--- PASS: TestScanRedis (0.00s)
	redis_test.go:36: dial tcp 127.0.0.1:6379: getsockopt: connection refused {{127.0.0.1 6379   test} false}
PASS
ok  	command-line-arguments	0.025s
```

### MONGODB scan module

The mongodb scan module depends on the mgo package, which is available`go get`The command is installed directly.

```bash
go get gopkg.in/mgo.v2
```

Full code:

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

Test Results:

```bash
go test -v plugins/mongodb_test.go
=== RUN   TestScanMongodb
--- PASS: TestScanMongodb (3.53s)
	mongodb_test.go:36: no reachable servers {{127.0.0.1 27017 mongodb test test} false}
PASS
ok  	command-line-arguments	3.558s
```

### ELASTICSEARCH scan module

ELASTICSEARCH scan plugin depends on 3rd party packages`gopkg.in/olivere/elastic.v3`, also directly`go get`Install.
The complete code is as follows:

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

Test code:

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

The test results are as follows:

```bash
go test -v plugins/elastic_test.go
=== RUN   TestScanElastic
--- PASS: TestScanElastic (5.02s)
	elastic_test.go:36: no Elasticsearch node available {{127.0.0.1 9200 elastic root 123456} false}
PASS
ok  	command-line-arguments	5.061s
```

### Scan module plugin

The functions of the scanning plug-in we wrote earlier are the same, we can put this group of functions into a map, and automatically call different scanning plug-ins according to different protocols during the scanning process.

Newly added scanning plug-ins can be registered directly in this way.

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

## Scan task scheduling

Earlier, we wrote some weak password scanning plugins for common services, which also passed the test.
Next, we need to implement the function of passing the iplist, username dictionary and password dictionary from the command line parameters, and read the corresponding information for scanning and scheduling. To break it down, we need to do the following things:

-   read iplist list
-   Read username dictionary
-   Read password dictionary
-   Generate scan task
-   Scan task scheduling
-   scan task execution
-   save scan results
-   command line invocation shell

### Read ip\\username and password dictionary

This module mainly uses the standard library`bufio`package, read the file line by line, and directly generate the corresponding slice after filtering. The iplist supports the following formats:

```bash
127.0.0.1:3306|mysql
8.8.8.8:22
9.9.9.9:6379
108.61.223.105:2222|ssh
```

For standard ports, the program can automatically determine its protocol. For non-standard port protocols, a field needs to be added to mark the protocol.

In order to prevent our program from being abused by script kiddies, the old man does not provide functions such as port scanning and protocol identification. Security engineers can throw the results produced by their company's port scanner into this to scan.

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

Test code for reading IP list, username dictionary and password dictionary:

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

The test results of this module are as follows:

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

Among them, iplist is not completely read in the process of loading. It will be filtered once before the official scan, and the unreasonable ip and port pairs will be eliminated, so as not to affect the scanning efficiency. The code is as follows:

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

The function of querying the corresponding service through the standard port is defined in the vars package. In order to avoid circular imports between multiple packages, we centralize all global variables into a separate vars package.

`PortNames`The map is the service corresponding to the standard port. After adding a new scanning plug-in, the content of the map also needs to be updated.

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

### task scheduling

The task scheduling module includes the functions of generating scanning tasks, distributing and executing scanning tasks according to the specified number of coroutines.

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

Individual scan plugins do not have the function of specifying a timeout period, so we additionally provide a timeout function for all scan plugins to prevent individual coroutines from being blocked and affect the overall speed of the scanner.

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

The test code of the task scheduling module is as follows:

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

The test results are as follows:

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

So far, the core components of our scanner have been built, and then the shell that needs to be called by a high-level command line on the scanner has been successfully created.

### command line module

Command line control module, we define a cmd package separately, which depends on third-party packages`github.com/urfave/cli`。

In the cmd module, we define two commands for scanning and exporting scan results as txt files and a system global option.

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

then back to`x-crack/util`The package writes an Action specifically for our scan command module, as follows:

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

then to`x-crack/models`Write an Action for the dump command, as follows:

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

Finally, add an angry progress bar to the IP\\port filtering and task scanning modules, and our scanner is done.

`x-crack/util/util.go`code snippet:

```go

func CheckAlive(ipList []models.IpAddr) ([]models.IpAddr) {
	logger.Log.Infoln("checking ip active")
	vars.ProcessBarActive = pb.StartNew(len(ipList))
	vars.ProcessBarActive.SetTemplate(`{{ rndcolor "Checking progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor}}  {{rtime . | rndcolor }}`)
....
```

`x-crack/util/task.go`The code snippet:

```go
func DistributionTask(tasks []models.Service) () {
	totalTask := len(tasks)
	scanBatch := totalTask / vars.ScanNum
	logger.Log.Infoln("Start to scan")
	vars.ProgressBar = pb.StartNew(totalTask)
	vars.ProgressBar.SetTemplate(`{{ rndcolor "Scanning progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor }} {{rtime . | rndcolor}} `)
...
```

There are still some details in the scanner code that are not detailed in the tutorial. Interested students can think about the following questions, and then combine the code to see how the old man implements:

1.  After scanning a weak password, how to cancel the request for the same IP\\port and user name to avoid low scanning efficiency
2.  For FTP anonymous access, how to record only one password instead of all usernames
3.  For a service like Redis without a username, how to record the password only once, instead of recording all the combinations of all users and normal passwords
4.  For scanning plugins that do not support setting timeout, how to set timeout uniformly

## Scanner test

So far, our scanner has been completed, you can compile it and run it to see the effect. The following script can simultaneously compile executable files for mac, linux and Windows platforms with one click (the author's development environment is MAC)

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

### Use parameters

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

### Use screenshots

![](https://docs.xsec.io/images/x-crack/x-crack001.png)

![](https://docs.xsec.io/images/x-crack/x-crack002.png)
