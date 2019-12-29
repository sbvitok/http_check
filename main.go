// http_check project main.go
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Объявляем глобальные переменные.
var (
	resolver    *DnsResolver
	wd          sync.WaitGroup
	wr          sync.WaitGroup
	client      *http.Client
	concurrency *uint
	url         string
	keepalive   *bool
)

// Создаем структуру для хранения ip адресов для отрезолвленных доменов
type DomIp struct {
	Dom  string
	Ip   net.IP
	Body string
}

// Структура для хранения серверов через которые будем произовдить resolv
type DnsResolver struct {
	Servers    []string
	RetryTimes int
}

// Парсим командную строку на интересующие нас аргументы, и заполняем глобальные переменные.
func init() {
	resf := flag.String("s", "8.8.8.8,8.8.4.4", "DNS servers, comma separated")
	timef := flag.Uint("t", 10, "Check timeout in seconds")
	concurrency = flag.Uint("c", 20, "Checks concurrency")
	urlf := flag.String("u", "/nagios_check.php", "URL to check")
	port := flag.Uint("p", 80, "Port number for check")
	resolvconf := flag.String("r", "", "Path to resolv.conf")
	keepalive = flag.Bool("k", false, "Turn on KeepAlive connections")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] dom1 dom2 dom3 ...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *resolvconf != "" {
		var err error
		resolver, err = NewFromResolvConf(*resolvconf)
		if err != nil {
			panic(err)
		}
	} else {
		resolver = NewResolver(strings.Split(*resf, ","))
	}
	timeout := time.Duration(time.Second * time.Duration(*timef))
	client = &http.Client{Timeout: timeout}
	url = fmt.Sprintf(":%v%s", *port, *urlf)
}

// Создаем из масива строк (ip адресов) объект хранящий информацию
// о серверах через которые будем производить resolv
func NewResolver(servers []string) *DnsResolver {
	for i := range servers {
		servers[i] += ":53"
	}

	return &DnsResolver{servers, len(servers) * 2}
}

// Создаем объект хранящий информацию о серверах резолва из пути к файлу (resolv.conf)
func NewFromResolvConf(path string) (*DnsResolver, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &DnsResolver{}, errors.New("no such file or directory: " + path)
	}
	config, err := dns.ClientConfigFromFile(path)
	servers := []string{}
	for _, ipAddress := range config.Servers {
		servers = append(servers, ipAddress+":53")
	}
	return &DnsResolver{servers, len(servers) * 2}, err
}

// Публичная функция для поиска ip адреса домена.
func (r *DnsResolver) LookupHost(host string) ([]net.IP, error) {
	return r.lookupHost(host, r.RetryTimes)
}

// Приватная функция для поиска ip адреса домена. Прнимимает имя домена
// и количество попыток резолва в случаяе ошибки. В случае ошибки резолва
// функция рекурсивно вызывает сама себя, пока количество попыток отрезолвить
// домен не будет исчерпано.
func (r *DnsResolver) lookupHost(host string, triesLeft int) ([]net.IP, error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(host), dns.TypeA, dns.ClassINET}
	in, err := dns.Exchange(m1, r.Servers[rand.Intn(len(r.Servers))])

	result := []net.IP{}

	switch {
	case err != nil:
		if strings.HasSuffix(err.Error(), "i/o timeout") && triesLeft > 0 {
			triesLeft--
			return r.lookupHost(host, triesLeft)
		}
		return result, err
	case in != nil && in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused:
		if triesLeft > 0 {
			triesLeft--
			return r.lookupHost(host, triesLeft)
		}
		return result, errors.New(dns.RcodeToString[in.Rcode])
	case in != nil && in.Rcode != dns.RcodeSuccess:
		return result, errors.New(dns.RcodeToString[in.Rcode])
	}

	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			result = append(result, t.A)
		}
	}
	return result, err
}

// Многопоточная функция резолва ip адресов, принимает канал из которого брать
// задания, и канал в который отправлять результаты выполнения задания.
func resolv(jobs <-chan string, results chan<- DomIp) {
	defer wd.Done()
	for dom := range jobs {
		domip := DomIp{Dom: dom}
		if ip := net.ParseIP(dom); ip != nil {
			domip.Ip = ip
			results <- domip
			continue
		}
		ips, err := resolver.LookupHost(dom)
		if err != nil {
			results <- domip
		} else {
			domip.Ip = ips[0]
			results <- domip
		}
	}
}

// Функция выплняющая http запросы к отрезолвленным доменам. В случае успешного
// выполнения возвращает nil, в случае ошибки возвращает ошибку.
func httpReq(domip *DomIp) error {
	ip := domip.Ip.String()
	req, e := http.NewRequest("GET", "http://"+ip+url, nil)
	if e != nil {
		panic(e)
	}
	req.Host = domip.Dom
	a, err := client.Do(req)
	if err != nil {
		return err
	} else if a.StatusCode != 200 {
		defer a.Body.Close()
		if *keepalive {
			body, _ := ioutil.ReadAll(a.Body)
			domip.Body = string(body)
		}
		return errors.New("Answer != 200")
	}
	defer a.Body.Close()
	if *keepalive {
		body, _ := ioutil.ReadAll(a.Body)
		domip.Body = string(body)
	}
	return nil
}

// Многопоточная функция проверки типов ошибок домена. Прнимает канал со списоком заданий
// (отрезолвленных доменов), канал в который будет сбрасывать ошибки резолва домена,
// и канал в который будет отправлять ошибки выполнения http запросов.
func resParse(doms <-chan DomIp, dnsErrors chan<- string, httpErrors chan<- DomIp) {
	defer wr.Done()
	for domip := range doms {
		if domip.Ip == nil {
			dnsErrors <- domip.Dom
		} else {
			if err := httpReq(&domip); err != nil {
				httpErrors <- domip
			}

		}
	}
}

// Фунция запуска многопоточной функции проверки типов ошибок домена.
func reqGo(doms <-chan DomIp, dnsErrors chan<- string, httpErrors chan<- DomIp) {
	for r := uint(1); r <= *concurrency; r++ {
		wr.Add(1)
		go resParse(doms, dnsErrors, httpErrors)
	}
}

// Функция удаления повторяющихся аргументов (доменов) командной строки.
func removeDuplicates(elements []string) (result []string) {

	for i := 0; i < len(elements); i++ {
		// Scan slice for a previous element of the same value.
		exists := false
		for v := 0; v < i; v++ {
			if elements[v] == elements[i] {
				exists = true
				break
			}
		}
		// If no previous element exists, append this one.
		if !exists {
			result = append(result, elements[i])
		}
	}
	return
}

func main() {

	doms := removeDuplicates(flag.Args())
	dnsJobs := make(chan string)
	dnsRes := make(chan DomIp)
	dnsErrors := make(chan string, len(doms))
	httpErr1Pass := make(chan DomIp, len(doms))
	httpErr2Pass := make(chan DomIp, len(doms))

	for d := uint(1); d <= *concurrency; d++ {
		wd.Add(1)
		go resolv(dnsJobs, dnsRes)
	}

	reqGo(dnsRes, dnsErrors, httpErr1Pass)

	for _, dom := range doms {
		dnsJobs <- dom
	}

	close(dnsJobs)
	wd.Wait()
	close(dnsRes)
	wr.Wait()
	close(dnsErrors)
	close(httpErr1Pass)

	if len(httpErr1Pass) != 0 && len(httpErr1Pass) <= 10 {
		reqGo(httpErr1Pass, dnsErrors, httpErr2Pass)
		wr.Wait()
		close(httpErr2Pass)
	} else {
		httpErr2Pass = httpErr1Pass
	}

	e := 0

	if len(dnsErrors)+len(httpErr2Pass) == 0 {
		fmt.Print("All domains passed PHP check")
	}

	if len(httpErr2Pass) != 0 {
		fmt.Print("PHP_CRITICAL: ")
		for domip := range httpErr2Pass {
			fmt.Printf("%s ", domip.Dom)
		}
		e++
	}

	if len(dnsErrors) != 0 {
		fmt.Print("DNS_CRITICAL: ")
		for dom := range dnsErrors {
			fmt.Printf("%s ", dom)
		}
		e++
	}

	fmt.Print("\n")

	if e != 0 {
		os.Exit(2)
	}

}
