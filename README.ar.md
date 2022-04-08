# "دورة تطوير الأمان" أول ماسح ضوئي ضعيف لكلمات المرور (x-crack) للشباب

## الاستخدام

    x-crack scan -i iplist.txt -u user.txt -p pass.txt -t 15

    [0000]  INFO xsec crack: checking ip active
    Checking progress:  [100.00%] [5/5]
    [0000]  INFO xsec crack: Ip: x.x.x.211, Port: 22, Protocol: [SSH], Username: admin, Password: admin
    [0000]  INFO xsec crack: Ip: x.x.x.9, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.56, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.236, Port: 22, Protocol: [SSH], Username: admin, Password: 123456
    [0001]  INFO xsec crack: Ip: x.x.x.134, Port: 22, Protocol: [SSH], Username: admin, Password: 123456

## ملخص

عندما نقوم بأمان المؤسسة ، فإن الكشف عن كلمة المرور الضعيفة هو أحد الأجزاء الأساسية لأمن النظام / الشبكة. وفقًا للتجربة ، غالبًا ما تظهر الخدمات ذات كلمات المرور الضعيفة على النحو التالي:

-   بروتوكول نقل الملفات
-   SSH
-   SMB
-   MYSQL
-   MSSQL
-   بوستجرسكل
-   ريديس
-   منغودب
-   مطاط

ثم دعونا نستخدم GO لكتابة ماسح ضوئي ضعيف لكلمة المرور للخدمات المشتركة ، ودعم إضافة وحدات فحص خدمة جديدة في شكل مكونات إضافية. تم جدولة برنامجنا التعليمي مبدئيًا لفحص الخدمات المذكورة أعلاه فقط.

امنح الماسح اسماً مجنوناً`x-crack`، بعد إنشاء مشروع x-crack في $ GOPATH / src / ، ابدأ البرمجة. لا تخبرني عن المبادئ الأساسية ونواة إطار العمل. الرجل العجوز هو مجرد مكوك عندما يتعلق الأمر بالبرمجة.

عنوان المشروع المكتمل هو:[هتبص://جذب.كوم/نيتكسفلي/كسكرك](https://github.com/netxfly/x-crack)

## البداية

### تعريف بنية البيانات

-   محتوى إدخال وحدة المسح هو قائمة IP والمنافذ والبروتوكول ، نحتاج إلى تحديد بنية بيانات IpAddr ؛
-   المعلمات التي يجب تمريرها في كل عملية مسح لكل خدمة هي IP ، والمنفذ ، والبروتوكول ، واسم المستخدم وكلمة المرور ، ويجب تحديد بنية الخدمة لتضمين هذه المحتويات ؛
-   بعد تجربة كل سجل خدمة بواسطة وحدة المسح ، سيتم الحصول على نتيجة المسح أم لا ، وسوف نحدد بنية بيانات ScanResult.

وفقًا لمواصفات التطوير ، يتم وضع تعريف بنية البيانات بشكل موحد في دليل النماذج ، ويتم تحديد جميع هياكل البيانات على النحو التالي:

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

### وحدة مسح FTP

تحتوي لغة go على وحدة FTP جاهزة ، ونجد الوحدة التي تحتوي على أكبر عدد من النجوم مباشرةً`go get`فقط قم بتثبيته واستخدامه:

```bash
go get -u github.com/jlaffaye/ftp
```

نضع جميع وحدات المسح`plugins`في الدليل ، يكون البرنامج المساعد للمسح لبروتوكول FTP كما يلي:

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

每个连接需要设置超时时间，防止因网络问题导致的阻塞，我们打算通过程序的命令行来控制超时时间，所以定义了一个全局变量TimeOut。
放在vars模块中的原因是防止放在这个模块中后会和其他模块互相调用导致的循环import

على الرغم من أنه من الممكن كتابة الكود في وقت قصير ، لا يمكننا الانتظار حتى يتم كتابة عشرات الآلاف من الأسطر ثم تشغيلها. على سبيل المثال ، هدفنا هو بناء سيارة فاخرة ، لا يمكننا الانتظار حتى يتم تصميم جميع الأجزاء وتثبيتها قبل بدء اختبار السيارة. ، عملية التطوير الصحيحة هي الاختبار أثناء الكتابة ، وليس الانتظار حتى يتم بناء العجلة ، ولكن للاختبار في مرحلة المسامير والتروس.

ما يلي هو رمز الاختبار ونتيجة معدات البرنامج الإضافي لمسح بروتوكول نقل الملفات.

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

تتوافق نتائج الاختبار مع التوقعات ، مما يشير إلى أن الجزء الخاص بنا ليس منتجًا معيبًا ، ويمكننا الاستمرار في إعادة تصنيع الأجزاء الأخرى.

```bash
$ go test -v plugins/ftp_test.go
=== RUN   TestScanFtp
--- PASS: TestScanFtp (0.00s)
	ftp_test.go:36: dial tcp 127.0.0.1:21: getsockopt: connection refused {{127.0.0.1 21 ftp ftp ftp} false}
PASS
ok  	command-line-arguments	0.025s
```

### وحدة المسح SSH

تأتي مكتبة go القياسية مع حزمة ssh ، والتي يمكن استدعاؤها مباشرة.الكود الكامل هو كما يلي:

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

وبالمثل ، بعد كتابة كل وحدة فرعية ، تحتاج إلى تشغيلها باستخدام اختبار go لمعرفة ما إذا كانت تفي بالتوقعات أم لا.كود الاختبار هو كما يلي:

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

نتائج الاختبار كالتالي:

```go
$ go test -v plugins/ssh_test.go
=== RUN   TestScanSsh
--- PASS: TestScanSsh (0.00s)
	ssh_test.go:36: dial tcp 127.0.0.1:22: getsockopt: connection refused {{127.0.0.1 22 ssh root 123456} false}
PASS
ok  	command-line-arguments	0.026s
```

### وحدة مسح SMB

استخدمنا البرنامج المساعد لفحص كلمة مرور SMB الضعيفة`github.com/stacktitan/smb/smb`الحزمة ، نفس الشيء مباشرة`go get`فقط قم بتثبيته واستخدامه.
تظهر الكود على النحو التالي:

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

اكتب أيضًا حالة اختبار لاختبارها أولاً ، ويكون رمز الاختبار كما يلي:

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

نتائج الإختبار:

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

### وحدات فحص MYSQL و MSSQL و POSTGRESQL

وحدات المسح الخاصة بـ MYSQL و MSSQL و POSTGRESQL ، أستخدم جهة خارجية ORM`xorm`، بالطبع ، يمكن أيضًا تنفيذه مباشرةً باستخدام برنامج تشغيل sql الأصلي ، وهو مناسب لنا لاستخدامه هنا.`xorm`مكوك.
ل`xorm`على سبيل المثال ، تتشابه طرق تنفيذ هذه المكونات الإضافية الثلاثة للمسح. من أجل توفير مساحة ، ننظر فقط إلى تنفيذ المكون الإضافي mysql scanning. بالنسبة إلى المكونين الإضافيين الآخرين ، يمكنك الرجوع إلى كود المصدر في جيثب.
أولا أو أولا`go get`حزم للاستخدام:

```bash
go get github.com/netxfly/mysql
go get github.com/go-xorm/xorm
github.com/go-xorm/core
```

بعد ذلك ، نقوم بتمرير IP والمنفذ واسم المستخدم وكلمة المرور ليتم التحقق منها كمصدر بيانات إلى xorm. الكود الكامل هو كما يلي:

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

قد يكون زملاء الدراسة حادو البصر قد لاحظوا ما سبق`github.com/netxfly/mysql`حزمة mysql هذه موضوعة تحت github للمؤلف ، لماذا هذا؟

لأنك إذا استخدمت حزمة mysql مباشرة ، فسوف تصادف`[mysql] packets.go:33: unexpected EOF" error`يؤثر الإخراج غير الطبيعي لـ ، على جماليات واجهة المستخدم الناتجة لبرنامجنا أثناء عملية المسح. هذا غير مقبول بالنسبة لي الوسيم. لا يمكن حله عن طريق تعيين المعلمات. في النهاية ، اضطررت إلى تفرع حزمة mysql مباشرة وطباعتها يتم التعليق على هذا البيان غير الطبيعي ثم إرساله للاستخدام المباشر.

كود الاختبار:

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

نتائج الإختبار:

```bash
go test -v plugins/mysql_test.go
=== RUN   TestScanMysql
--- PASS: TestScanMysql (0.02s)
	mysql_test.go:36: Error 1045: Access denied for user 'root'@'10.10.10.100' (using password: YES) {{10.10.10.10 3306 mysql root 123456} false}
PASS
ok  	command-line-arguments	0.041s
```

### وحدة المسح Redis

`go get`قم بتثبيت حزم الطرف الثالث`github.com/go-redis/redis`، الكود الكامل كما يلي:

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

كود الاختبار:

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

نتائج الإختبار:

```bash
go test -v plugins/redis_test.go
=== RUN   TestScanRedis
--- PASS: TestScanRedis (0.00s)
	redis_test.go:36: dial tcp 127.0.0.1:6379: getsockopt: connection refused {{127.0.0.1 6379   test} false}
PASS
ok  	command-line-arguments	0.025s
```

### وحدة مسح MONGODB

تعتمد وحدة فحص mongodb على حزمة mgo المتوفرة`go get`يتم تثبيت الأمر مباشرة.

```bash
go get gopkg.in/mgo.v2
```

الكود الكامل:

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

نتائج الإختبار:

```bash
go test -v plugins/mongodb_test.go
=== RUN   TestScanMongodb
--- PASS: TestScanMongodb (3.53s)
	mongodb_test.go:36: no reachable servers {{127.0.0.1 27017 mongodb test test} false}
PASS
ok  	command-line-arguments	3.558s
```

### وحدة مسح ضوئي ELASTICSEARCH

يعتمد المكون الإضافي ELASTICSEARCH للمسح الضوئي على حزم الطرف الثالث`gopkg.in/olivere/elastic.v3`، بشكل مباشر أيضًا`go get`ثَبَّتَ.
الكود الكامل كما يلي:

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

كود الاختبار:

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

نتائج الاختبار كالتالي:

```bash
go test -v plugins/elastic_test.go
=== RUN   TestScanElastic
--- PASS: TestScanElastic (5.02s)
	elastic_test.go:36: no Elasticsearch node available {{127.0.0.1 9200 elastic root 123456} false}
PASS
ok  	command-line-arguments	5.061s
```

### مسح وحدة البرنامج المساعد

وظائف المكون الإضافي للمسح الضوئي التي كتبناها سابقًا هي نفسها ، يمكننا وضع هذه المجموعة من الوظائف في خريطة ، واستدعاء المكونات الإضافية للمسح الضوئي تلقائيًا وفقًا لبروتوكولات مختلفة أثناء عملية المسح.

يمكن تسجيل المكونات الإضافية للمسح الضوئي المضافة حديثًا مباشرةً بهذه الطريقة.

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

## مسح جدولة المهام

في وقت سابق ، كتبنا بعض المكونات الإضافية الضعيفة لفحص كلمات المرور للخدمات المشتركة ، والتي اجتازت الاختبار أيضًا.
بعد ذلك ، نحتاج إلى تنفيذ وظيفة تمرير iplist ، وقاموس اسم المستخدم ، وقاموس كلمة المرور من معلمات سطر الأوامر ، وقراءة المعلومات المقابلة للمسح والجدولة. ولتقسيمها ، نحتاج إلى القيام بالأمور التالية:

-   قراءة قائمة iplist
-   قراءة قاموس اسم المستخدم
-   قراءة قاموس كلمة المرور
-   إنشاء مهمة الفحص
-   مسح جدولة المهام
-   فحص تنفيذ المهمة
-   حفظ نتائج الفحص
-   قذيفة استدعاء سطر الأوامر

### قراءة ip \\ اسم المستخدم وكلمة المرور قاموس

تستخدم هذه الوحدة بشكل أساسي المكتبة القياسية`bufio`包，逐行读取文件，进行过滤后直接生成相应的slice。其中iplist支持以下格式：

```bash
127.0.0.1:3306|mysql
8.8.8.8:22
9.9.9.9:6379
108.61.223.105:2222|ssh
```

بالنسبة للمنافذ القياسية ، يمكن للبرنامج تحديد البروتوكول الخاص به تلقائيًا.بالنسبة لبروتوكولات المنافذ غير القياسية ، يجب إضافة حقل لتمييز البروتوكول.

من أجل منع إساءة استخدام برنامجنا من قبل أطفال البرنامج النصي ، لا يوفر الرجل العجوز وظائف مثل فحص المنفذ وتحديد البروتوكول. يمكن لمهندسي الأمن إلقاء النتائج التي تنتجها الماسح الضوئي للمنافذ التابع لشركتهم في هذا الفحص.

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

رمز اختبار لقراءة قائمة IP وقاموس اسم المستخدم وقاموس كلمة المرور:

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

نتائج اختبار هذه الوحدة هي كما يلي:

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

من بينها ، لا يتم قراءة iplist بالكامل في عملية التحميل. سيتم تصفيته مرة واحدة قبل الفحص الرسمي ، وسيتم التخلص من أزواج IP والمنافذ غير المعقولة ، حتى لا تؤثر على كفاءة المسح. الرمز كما يلي:

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

يتم تحديد وظيفة الاستعلام عن الخدمة المقابلة من خلال المنفذ القياسي في حزمة vars. من أجل تجنب الاستيراد الدائري بين الحزم المتعددة ، نقوم بتجميع جميع المتغيرات العامة في حزمة vars منفصلة.

`PortNames`الخريطة هي الخدمة المطابقة للمنفذ القياسي. بعد إضافة مكون إضافي جديد للمسح ، يحتاج محتوى هذه الخريطة إلى التحديث.

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

### جدولة المهام

تتضمن وحدة جدولة المهام وظائف إنشاء مهام المسح وتوزيع مهام المسح وتنفيذها وفقًا لعدد محدد من coroutines.

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

لا تحتوي المكونات الإضافية للفحص الفردي على وظيفة تحديد المهلة ، لذلك نحن نوفر بالإضافة إلى ذلك وظيفة المهلة لجميع المكونات الإضافية للمسح الضوئي لمنع حظر coroutines الفردية والتأثير على السرعة الإجمالية للماسح الضوئي.

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

كود الاختبار لوحدة جدولة المهام كما يلي:

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

نتائج الاختبار كالتالي:

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

حتى الآن ، تم بناء المكونات الأساسية لجهاز المسح الخاص بنا ، ومن ثم تم بنجاح إنشاء الغلاف الذي يحتاج إلى استدعاء بواسطة سطر أوامر عالي المستوى على الماسح الضوئي.

### وحدة سطر الأوامر

وحدة التحكم في سطر الأوامر ، نحدد حزمة cmd بشكل منفصل ، والتي تعتمد على حزم الطرف الثالث`github.com/urfave/cli`。

في الوحدة النمطية cmd ، نحدد أمرين لمسح نتائج الفحص وتصديرها كملفات txt وخيار عالمي للنظام.

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

ثم العودة إلى`x-crack/util`تكتب الحزمة إجراءً خاصًا لوحدة أوامر الفحص الخاصة بنا ، على النحو التالي:

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

ثم إلى`x-crack/models`اكتب إجراء لأمر التفريغ ، على النحو التالي:

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

أخيرًا ، أضف شريط تقدم غاضب إلى وحدات تصفية IP \\ المنفذ ومسح المهام ، وقد تم الانتهاء من الماسح الضوئي الخاص بنا.

`x-crack/util/util.go`مقتطف الشفرة:

```go

func CheckAlive(ipList []models.IpAddr) ([]models.IpAddr) {
	logger.Log.Infoln("checking ip active")
	vars.ProcessBarActive = pb.StartNew(len(ipList))
	vars.ProcessBarActive.SetTemplate(`{{ rndcolor "Checking progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor}}  {{rtime . | rndcolor }}`)
....
```

`x-crack/util/task.go`مقتطف الشفرة:

```go
func DistributionTask(tasks []models.Service) () {
	totalTask := len(tasks)
	scanBatch := totalTask / vars.ScanNum
	logger.Log.Infoln("Start to scan")
	vars.ProgressBar = pb.StartNew(totalTask)
	vars.ProgressBar.SetTemplate(`{{ rndcolor "Scanning progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor }} {{rtime . | rndcolor}} `)
...
```

لا تزال هناك بعض التفاصيل في رمز الماسح الضوئي التي لم يتم تفصيلها في البرنامج التعليمي. يمكن للطلاب المهتمين التفكير في الأسئلة التالية ، ثم دمج الرمز لمعرفة كيفية تنفيذ الرجل العجوز:

1.  بعد مسح كلمة مرور ضعيفة ، كيفية إلغاء الطلب لنفس IP \\ المنفذ واسم المستخدم لتجنب انخفاض كفاءة المسح
2.  للوصول المجهول إلى FTP ، كيفية تسجيل كلمة مرور واحدة فقط بدلاً من جميع أسماء المستخدمين
3.  بالنسبة لخدمة مثل Redis بدون اسم مستخدم ، كيفية تسجيل كلمة المرور مرة واحدة فقط ، بدلاً من تسجيل جميع مجموعات جميع المستخدمين وكلمات المرور العادية
4.  لمسح المكونات الإضافية التي لا تدعم إعداد مهلة ، كيفية ضبط المهلة بشكل موحد

## اختبار الماسح الضوئي

حتى الآن ، تم الانتهاء من الماسح الخاص بنا ، يمكنك تجميعه وتشغيله لمعرفة التأثير. يمكن للبرنامج النصي التالي تجميع الملفات القابلة للتنفيذ في وقت واحد لأنظمة mac و linux و Windows بنقرة واحدة (بيئة تطوير المؤلف هي MAC)

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

### استخدم المعلمات

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

### استخدم لقطات الشاشة

![](https://docs.xsec.io/images/x-crack/x-crack001.png)

![](https://docs.xsec.io/images/x-crack/x-crack002.png)
