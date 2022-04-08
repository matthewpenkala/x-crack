# "सुरक्षा विकास पाठ्यक्रम" युवा लोगों के लिए पहला कमजोर पासवर्ड स्कैनर (एक्स-क्रैक)

## प्रयोग

    x-crack scan -i iplist.txt -u user.txt -p pass.txt -t 15

    [0000]  INFO xsec crack: checking ip active
    Checking progress:  [100.00%] [5/5]
    [0000]  INFO xsec crack: Ip: x.x.x.211, Port: 22, Protocol: [SSH], Username: admin, Password: admin
    [0000]  INFO xsec crack: Ip: x.x.x.9, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.56, Port: 22, Protocol: [SSH], Username: root, Password: 123456
    [0000]  INFO xsec crack: Ip: x.x.x.236, Port: 22, Protocol: [SSH], Username: admin, Password: 123456
    [0001]  INFO xsec crack: Ip: x.x.x.134, Port: 22, Protocol: [SSH], Username: admin, Password: 123456

## अवलोकन

जब हम एंटरप्राइज़ सुरक्षा कर रहे होते हैं, तो कमजोर पासवर्ड का पता लगाना सिस्टम/नेटवर्क सुरक्षा के सबसे बुनियादी हिस्सों में से एक है। अनुभव के अनुसार, कमजोर पासवर्ड वाली सेवाएं अक्सर इस प्रकार दिखाई देती हैं:

-   एफ़टीपी
-   एसएसएच
-   एसएमबी
-   माई एसक्यूएल
-   एमएसएसक्यूएल
-   पोस्टग्रेएसक्यूएल
-   रेडिस
-   मोंगोडब
-   Elasticsearch

तो चलिए सामान्य सेवाओं के लिए कमजोर पासवर्ड स्कैनर लिखने के लिए GO का उपयोग करते हैं, और प्लग-इन के रूप में नए सर्विस स्कैनिंग मॉड्यूल जोड़ने का समर्थन करते हैं। हमारा ट्यूटोरियल अस्थायी रूप से केवल उपरोक्त सेवाओं को स्कैन करने के लिए निर्धारित है।

स्कैनर को एक पागल नाम दें`x-crack`, $GOPATH/src/ में एक एक्स-क्रैक प्रोजेक्ट बनाने के बाद, कोडिंग शुरू करें। मुझे अंतर्निहित सिद्धांतों और फ्रेमवर्क कर्नेल के बारे में न बताएं। जब कोडिंग की बात आती है तो बूढ़ा सिर्फ एक शटल होता है।

पूर्ण परियोजना का पता है:[हत्तपः://गिटहब.कॉम/नेटसफली/क्ष-क्रैक](https://github.com/netxfly/x-crack)

## प्रारंभ

### डेटा संरचना परिभाषा

-   स्कैनिंग मॉड्यूल की इनपुट सामग्री आईपी, पोर्ट और प्रोटोकॉल की एक सूची है, हमें आईपीएडीआर की डेटा संरचना को परिभाषित करने की आवश्यकता है;
-   प्रत्येक सेवा के प्रत्येक स्कैन में पारित किए जाने वाले पैरामीटर आईपी, पोर्ट, प्रोटोकॉल, उपयोगकर्ता नाम और पासवर्ड हैं, और इन सामग्रियों को शामिल करने के लिए एक सेवा संरचना को परिभाषित करने की आवश्यकता है;
-   स्कैनिंग मॉड्यूल द्वारा प्रत्येक सेवा रिकॉर्ड की कोशिश करने के बाद, स्कैनिंग परिणाम प्राप्त होगा या नहीं, और हम स्कैन रिसेट डेटा संरचना को परिभाषित करेंगे।

विकास विनिर्देश के अनुसार, डेटा संरचना की परिभाषा को समान रूप से मॉडल निर्देशिका में रखा गया है, और सभी डेटा संरचनाओं को निम्नानुसार परिभाषित किया गया है:

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

### एफ़टीपी स्कैनिंग मॉड्यूल

गो भाषा में एक तैयार एफ़टीपी मॉड्यूल है, हम सीधे सबसे बड़ी संख्या में सितारों के साथ पाते हैं`go get`बस इसे स्थापित करें और इसका उपयोग करें:

```bash
go get -u github.com/jlaffaye/ftp
```

हम सभी स्कैन मॉड्यूल डालते हैं`plugins`निर्देशिका में, एफ़टीपी प्रोटोकॉल के लिए स्कैनिंग प्लगइन इस प्रकार है:

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

नेटवर्क समस्याओं के कारण अवरुद्ध होने से रोकने के लिए प्रत्येक कनेक्शन को एक टाइमआउट अवधि निर्धारित करने की आवश्यकता होती है। हम प्रोग्राम की कमांड लाइन के माध्यम से टाइमआउट अवधि को नियंत्रित करने का इरादा रखते हैं, इसलिए एक वैश्विक चर TimeOut परिभाषित किया गया है।
इसे वर्र्स मॉड्यूल में रखने का कारण सर्कुलर आयात को इस मॉड्यूल में रखे जाने के बाद एक दूसरे को अन्य मॉड्यूल के साथ कॉल करने से रोकना है।

हालांकि कम समय में कोड लिखना संभव है, हम हजारों लाइनों के लिखे जाने और फिर चलने का इंतजार नहीं कर सकते। उदाहरण के लिए, हमारा लक्ष्य एक लग्जरी कार बनाना है, हम सभी भागों के डिजाइन होने की प्रतीक्षा नहीं कर सकते। और कार परीक्षण शुरू करने से पहले स्थापित। , सही विकास प्रक्रिया लिखते समय परीक्षण करना है, पहिया बनने की प्रतीक्षा नहीं करना है, बल्कि शिकंजा और गियर के स्तर पर परीक्षण करना है।

एफ़टीपी स्कैनिंग प्लगइन के गियर का परीक्षण कोड और परिणाम निम्नलिखित है।

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

परीक्षण के परिणाम अपेक्षाओं को पूरा करते हैं, यह दर्शाता है कि हमारा हिस्सा एक दोषपूर्ण उत्पाद नहीं है, और हम अन्य भागों का पुन: निर्माण जारी रख सकते हैं।

```bash
$ go test -v plugins/ftp_test.go
=== RUN   TestScanFtp
--- PASS: TestScanFtp (0.00s)
	ftp_test.go:36: dial tcp 127.0.0.1:21: getsockopt: connection refused {{127.0.0.1 21 ftp ftp ftp} false}
PASS
ok  	command-line-arguments	0.025s
```

### SSH स्कैनिंग मॉड्यूल

गो का मानक पुस्तकालय ssh पैकेज के साथ आता है, जिसे सीधे कहा जा सकता है। पूरा कोड इस प्रकार है:

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

इसी तरह, प्रत्येक सबमॉड्यूल लिखे जाने के बाद, आपको यह देखने के लिए गो टेस्ट के साथ चलाने की जरूरत है कि क्या यह अपेक्षाओं को पूरा करता है। परीक्षण कोड इस प्रकार है:

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

परीक्षण के परिणाम इस प्रकार हैं:

```go
$ go test -v plugins/ssh_test.go
=== RUN   TestScanSsh
--- PASS: TestScanSsh (0.00s)
	ssh_test.go:36: dial tcp 127.0.0.1:22: getsockopt: connection refused {{127.0.0.1 22 ssh root 123456} false}
PASS
ok  	command-line-arguments	0.026s
```

### एसएमबी स्कैन मॉड्यूल

SMB कमजोर पासवर्ड स्कैनिंग प्लगइन, हमने इस्तेमाल किया`github.com/stacktitan/smb/smb`पैकेज, वही सीधे`go get`बस इसे इंस्टॉल करें और इसका इस्तेमाल करें।
कोड शो नीचे के रूप में:

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

पहले इसका परीक्षण करने के लिए एक परीक्षण मामला भी लिखें। परीक्षण कोड इस प्रकार है:

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

परीक्षण के परिणाम:

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

### MYSQL, MSSQL और POSTGRESQL स्कैन मॉड्यूल

MYSQL, MSSQL और POSTGRESQL के लिए स्कैनिंग मॉड्यूल, मैं एक तृतीय-पक्ष ORM का उपयोग करता हूं`xorm`, निश्चित रूप से, इसे सीधे देशी sql ड्राइवर का उपयोग करके भी लागू किया जा सकता है, जो हमारे लिए यहां उपयोग करने के लिए सुविधाजनक है।`xorm`एक शटल।
के लिए`xorm`उदाहरण के लिए, इन तीन स्कैनिंग प्लग-इन के कार्यान्वयन के तरीके समान हैं। स्थान बचाने के लिए, हम केवल mysql स्कैनिंग प्लग-इन के कार्यान्वयन को देखते हैं। अन्य दो प्लग-इन के लिए, आप पूर्ण का उल्लेख कर सकते हैं जीथब में स्रोत कोड।
पहले या पहले`go get`उपयोग करने के लिए पैकेज:

```bash
go get github.com/netxfly/mysql
go get github.com/go-xorm/xorm
github.com/go-xorm/core
```

इसके बाद, हम xorm को डेटा स्रोत के रूप में सत्यापित करने के लिए IP, पोर्ट, उपयोगकर्ता नाम और पासवर्ड पास करते हैं। पूरा कोड इस प्रकार है:

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

तेज-तर्रार सहपाठियों ने देखा होगा, ऊपर`github.com/netxfly/mysql`यह mysql पैकेज लेखक के जीथब के नीचे रखा गया है, ऐसा क्यों है?

क्योंकि यदि आप सीधे mysql पैकेज का उपयोग करते हैं, तो आपका सामना होगा`[mysql] packets.go:33: unexpected EOF" error`का असामान्य आउटपुट, स्कैनिंग प्रक्रिया के दौरान हमारे प्रोग्राम के आउटपुट UI के सौंदर्यशास्त्र को प्रभावित करता है। यह सुंदर मेरे लिए अस्वीकार्य है। इसे पैरामीटर सेट करके हल नहीं किया जा सकता है। अंत में, मुझे सीधे एक MySQL पैकेज को फोर्क करना पड़ा और प्रिंट करना पड़ा इस असामान्य बयान पर टिप्पणी की जाती है और फिर सीधे उपयोग के लिए प्रस्तुत किया जाता है।

टेस्ट कोड:

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

परीक्षण के परिणाम:

```bash
go test -v plugins/mysql_test.go
=== RUN   TestScanMysql
--- PASS: TestScanMysql (0.02s)
	mysql_test.go:36: Error 1045: Access denied for user 'root'@'10.10.10.100' (using password: YES) {{10.10.10.10 3306 mysql root 123456} false}
PASS
ok  	command-line-arguments	0.041s
```

### रेडिस स्कैन मॉड्यूल

`go get`तृतीय-पक्ष पैकेज स्थापित करें`github.com/go-redis/redis`, पूरा कोड इस प्रकार है:

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

टेस्ट कोड:

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

परीक्षण के परिणाम:

```bash
go test -v plugins/redis_test.go
=== RUN   TestScanRedis
--- PASS: TestScanRedis (0.00s)
	redis_test.go:36: dial tcp 127.0.0.1:6379: getsockopt: connection refused {{127.0.0.1 6379   test} false}
PASS
ok  	command-line-arguments	0.025s
```

### MONGODB स्कैन मॉड्यूल

मोंगोडब स्कैन मॉड्यूल एमजीओ पैकेज पर निर्भर करता है, जो उपलब्ध है`go get`आदेश सीधे स्थापित किया गया है।

```bash
go get gopkg.in/mgo.v2
```

पूरा कोड:

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

परीक्षण के परिणाम:

```bash
go test -v plugins/mongodb_test.go
=== RUN   TestScanMongodb
--- PASS: TestScanMongodb (3.53s)
	mongodb_test.go:36: no reachable servers {{127.0.0.1 27017 mongodb test test} false}
PASS
ok  	command-line-arguments	3.558s
```

### लोचदार खोज स्कैन मॉड्यूल

ELASTICSEARCH स्कैन प्लगइन तीसरे पक्ष के पैकेज पर निर्भर करता है`gopkg.in/olivere/elastic.v3`, सीधे भी`go get`स्थापित करना।
पूरा कोड इस प्रकार है:

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

टेस्ट कोड:

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

परीक्षण के परिणाम इस प्रकार हैं:

```bash
go test -v plugins/elastic_test.go
=== RUN   TestScanElastic
--- PASS: TestScanElastic (5.02s)
	elastic_test.go:36: no Elasticsearch node available {{127.0.0.1 9200 elastic root 123456} false}
PASS
ok  	command-line-arguments	5.061s
```

### स्कैन मॉड्यूल प्लगइन

हमने पहले लिखे गए स्कैनिंग प्लग-इन के कार्य समान हैं, हम कार्यों के इस समूह को मानचित्र में रख सकते हैं, और स्कैनिंग प्रक्रिया के दौरान विभिन्न प्रोटोकॉल के अनुसार स्वचालित रूप से विभिन्न स्कैनिंग प्लग-इन को कॉल कर सकते हैं।

नए जोड़े गए स्कैनिंग प्लग-इन को इस तरह से सीधे पंजीकृत किया जा सकता है।

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

## स्कैन कार्य शेड्यूलिंग

इससे पहले, हमने सामान्य सेवाओं के लिए कुछ कमजोर पासवर्ड स्कैनिंग प्लगइन्स लिखे, जो परीक्षा में भी उत्तीर्ण हुए।
इसके बाद, हमें कमांड लाइन पैरामीटर से iplist, यूजरनेम डिक्शनरी और पासवर्ड डिक्शनरी को पास करने के कार्य को लागू करने की आवश्यकता है, और स्कैनिंग और शेड्यूलिंग के लिए संबंधित जानकारी को पढ़ें। इसे तोड़ने के लिए, हमें निम्नलिखित चीजें करने की आवश्यकता है:

-   आईपीएल सूची पढ़ें
-   उपयोगकर्ता नाम शब्दकोश पढ़ें
-   पासवर्ड डिक्शनरी पढ़ें
-   स्कैन कार्य उत्पन्न करें
-   स्कैन कार्य शेड्यूलिंग
-   स्कैन कार्य निष्पादन
-   स्कैन परिणाम सहेजें
-   कमांड लाइन आमंत्रण खोल

### आईपी ​​\\ उपयोगकर्ता नाम और पासवर्ड शब्दकोश पढ़ें

यह मॉड्यूल मुख्य रूप से मानक पुस्तकालय का उपयोग करता है`bufio`पैकेज, फ़ाइल लाइन को लाइन से पढ़ें, और फ़िल्टर करने के बाद सीधे संबंधित स्लाइस उत्पन्न करें। iplist निम्नलिखित स्वरूपों का समर्थन करता है:

```bash
127.0.0.1:3306|mysql
8.8.8.8:22
9.9.9.9:6379
108.61.223.105:2222|ssh
```

मानक पोर्ट के लिए, प्रोग्राम स्वचालित रूप से अपना प्रोटोकॉल निर्धारित कर सकता है। गैर-मानक पोर्ट प्रोटोकॉल के लिए, प्रोटोकॉल को चिह्नित करने के लिए एक फ़ील्ड को जोड़ने की आवश्यकता होती है।

स्क्रिप्ट किडीज़ द्वारा हमारे कार्यक्रम का दुरुपयोग होने से रोकने के लिए, बूढ़ा आदमी पोर्ट स्कैनिंग और प्रोटोकॉल पहचान जैसे कार्य प्रदान नहीं करता है। सुरक्षा इंजीनियर अपनी कंपनी के पोर्ट स्कैनर द्वारा उत्पादित परिणामों को स्कैन करने के लिए इसमें फेंक सकते हैं।

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

आईपी ​​सूची, उपयोगकर्ता नाम शब्दकोश और पासवर्ड शब्दकोश पढ़ने के लिए टेस्ट कोड:

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

इस मॉड्यूल के परीक्षा परिणाम इस प्रकार हैं:

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

उनमें से, लोडिंग की प्रक्रिया में iplist पूरी तरह से नहीं पढ़ा जाता है। इसे आधिकारिक स्कैन से पहले एक बार फ़िल्टर किया जाएगा, और अनुचित आईपी और पोर्ट जोड़े को समाप्त कर दिया जाएगा, ताकि स्कैनिंग दक्षता को प्रभावित न किया जा सके। कोड इस प्रकार है:

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

मानक पोर्ट के माध्यम से संबंधित सेवा को क्वेरी करने का कार्य vars पैकेज में परिभाषित किया गया है। कई पैकेजों के बीच परिपत्र आयात से बचने के लिए, हम सभी वैश्विक चर को एक अलग vars पैकेज में केंद्रीकृत करते हैं।

`PortNames`मानचित्र मानक पोर्ट के अनुरूप सेवा है। एक नया स्कैनिंग प्लग-इन जोड़ने के बाद, इस मानचित्र की सामग्री को अद्यतन करने की आवश्यकता है।

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

### कार्य शेड्यूलिंग

कार्य शेड्यूलिंग मॉड्यूल में निर्दिष्ट संख्या में कोरआउट के अनुसार स्कैनिंग कार्यों को उत्पन्न करने, वितरित करने और स्कैनिंग कार्यों को निष्पादित करने के कार्य शामिल हैं।

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

अलग-अलग स्कैन प्लगइन्स में टाइमआउट निर्दिष्ट करने का कार्य नहीं होता है, इसलिए हम सभी स्कैन प्लगइन्स के लिए एक टाइमआउट फ़ंक्शन भी प्रदान करते हैं ताकि व्यक्तिगत कोरआउट को अवरुद्ध होने से रोका जा सके और स्कैनर की समग्र गति को प्रभावित किया जा सके।

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

कार्य शेड्यूलिंग मॉड्यूल का परीक्षण कोड इस प्रकार है:

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

परीक्षण के परिणाम इस प्रकार हैं:

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

अब तक, हमारे स्कैनर के मुख्य घटकों का निर्माण किया गया है, और फिर स्कैनर पर एक उच्च-स्तरीय कमांड लाइन द्वारा कॉल किए जाने वाले शेल को सफलतापूर्वक बनाया गया है।

### कमांड लाइन मॉड्यूल

कमांड लाइन नियंत्रण मॉड्यूल, हम एक cmd पैकेज को अलग से परिभाषित करते हैं, जो तीसरे पक्ष के पैकेज पर निर्भर करता है`github.com/urfave/cli`。

cmd मॉड्यूल में, हम स्कैन परिणामों को स्कैन करने और निर्यात करने के लिए दो कमांड को txt फ़ाइलों और एक सिस्टम ग्लोबल विकल्प के रूप में परिभाषित करते हैं।

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

फिर वापस`x-crack/util`पैकेज विशेष रूप से हमारे स्कैन कमांड मॉड्यूल के लिए एक क्रिया लिखता है, जो इस प्रकार है:

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

फिर तो`x-crack/models`डंप कमांड के लिए एक क्रिया इस प्रकार लिखें:

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

अंत में, आईपी \\ पोर्ट फ़िल्टरिंग और टास्क स्कैनिंग मॉड्यूल में एक गुस्सा प्रगति पट्टी जोड़ें, और हमारा स्कैनर हो गया है।

`x-crack/util/util.go`सांकेतिक टुकड़ा:

```go

func CheckAlive(ipList []models.IpAddr) ([]models.IpAddr) {
	logger.Log.Infoln("checking ip active")
	vars.ProcessBarActive = pb.StartNew(len(ipList))
	vars.ProcessBarActive.SetTemplate(`{{ rndcolor "Checking progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor}}  {{rtime . | rndcolor }}`)
....
```

`x-crack/util/task.go`कोड स्निपेट:

```go
func DistributionTask(tasks []models.Service) () {
	totalTask := len(tasks)
	scanBatch := totalTask / vars.ScanNum
	logger.Log.Infoln("Start to scan")
	vars.ProgressBar = pb.StartNew(totalTask)
	vars.ProgressBar.SetTemplate(`{{ rndcolor "Scanning progress: " }} {{  percent . "[%.02f%%]" "[?]"| rndcolor}} {{ counters . "[%s/%s]" "[%s/?]" | rndcolor}} {{ bar . "「" "-" (rnd "ᗧ" "◔" "◕" "◷" ) "•" "」" | rndcolor }} {{rtime . | rndcolor}} `)
...
```

स्कैनर कोड में अभी भी कुछ विवरण हैं जो ट्यूटोरियल में विस्तृत नहीं हैं। इच्छुक छात्र निम्नलिखित प्रश्नों के बारे में सोच सकते हैं, और फिर कोड को जोड़कर देख सकते हैं कि बूढ़ा कैसे लागू करता है:

1.  कमजोर पासवर्ड को स्कैन करने के बाद, कम स्कैनिंग दक्षता से बचने के लिए उसी आईपी पोर्ट और उपयोगकर्ता नाम के अनुरोध को कैसे रद्द करें
2.  एफ़टीपी अनाम पहुंच के लिए, सभी उपयोगकर्ता नामों के बजाय केवल एक पासवर्ड कैसे रिकॉर्ड करें
3.  उपयोगकर्ता नाम के बिना रेडिस जैसी सेवा के लिए, सभी उपयोगकर्ताओं और सामान्य पासवर्ड के सभी संयोजनों को रिकॉर्ड करने के बजाय केवल एक बार पासवर्ड कैसे रिकॉर्ड करें
4.  ऐसे प्लगइन्स को स्कैन करने के लिए जो सेटिंग टाइमआउट का समर्थन नहीं करते हैं, टाइमआउट को समान रूप से कैसे सेट करें

## स्कैनर परीक्षण

अब तक, हमारा स्कैनर पूरा हो चुका है, आप इसे संकलित कर सकते हैं और प्रभाव देखने के लिए इसे चला सकते हैं। निम्नलिखित स्क्रिप्ट एक क्लिक के साथ मैक, लिनक्स और विंडोज प्लेटफॉर्म के लिए निष्पादन योग्य फाइलों को एक साथ संकलित कर सकती है (लेखक का विकास पर्यावरण मैक है)

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

### मापदंडों का प्रयोग करें

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

### स्क्रीनशॉट का प्रयोग करें

![](https://docs.xsec.io/images/x-crack/x-crack001.png)

![](https://docs.xsec.io/images/x-crack/x-crack002.png)
