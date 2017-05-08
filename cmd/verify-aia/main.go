/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jcjones/ct-sql/utils"
)

var timeout = time.Second * 10

var rootsFile = flag.String("roots", "roots.pem", "Trusted root CAs in PEM format")
var hostsFile = flag.String("hosts", "", "Hosts to test")
var numThreads = flag.Int("threads", 8, "Number of threads per core to use")

var authorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
var aiaOCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
var aiaIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

func decodeCert(cert *x509.Certificate) string {
	return fmt.Sprintf("%+v %+v", cert.Subject, cert.Extensions)
}

type AiaOutcome string

const (
	SuccessViaAiaFetch AiaOutcome = "OKviaAIA"
	Success                       = "Success"
	Failure                       = "Failure"
)

type TestResult struct {
	Result   AiaOutcome
	Hostname string
	Error    error
	Weight   uint64
}

type AiaState struct {
	Hostname   string
	RootCAList *x509.CertPool
	Weight     uint64
	ResultChan chan<- *TestResult
	ResultOnce sync.Once
}

func (self *AiaState) recordResult(result AiaOutcome, err error) {
	self.ResultOnce.Do(func() {
		self.ResultChan <- &TestResult{
			Result:   result,
			Weight:   self.Weight,
			Hostname: self.Hostname,
			Error:    err,
		}

		// fmt.Printf("%s %s\n", self.Hostname, result)
	})
}

func (self *AiaState) checkCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	var endEntity *x509.Certificate
	intermediates := x509.NewCertPool()

	for _, certAsn1 := range rawCerts {
		cert, err := x509.ParseCertificate(certAsn1)
		if err != nil {
			self.recordResult(Failure, err)
			return err
		}
		if endEntity == nil {
			endEntity = cert
		} else {
			intermediates.AddCert(cert)
		}
	}

	// Is this certList complete?
	_, err := endEntity.Verify(x509.VerifyOptions{
		DNSName:       self.Hostname,
		Intermediates: intermediates,
		Roots:         self.RootCAList,
	})

	if err == nil {
		// Didn't need AIA fetching, so we are done
		self.recordResult(Success, nil)
		return nil
	}

	foundAIA := false
	client := &http.Client{
		Timeout: timeout,
	}

	for _, aiaURL := range endEntity.IssuingCertificateURL {
		if !strings.HasPrefix(aiaURL, "http") {
			continue
		}
		foundAIA = true
		// Fetch AIA
		response, err := client.Get(aiaURL)
		if err != nil {
			self.recordResult(Failure, err)
			return err
		}

		defer response.Body.Close()
		certBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			self.recordResult(Failure, err)
			return err
		}

		fetchedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			self.recordResult(Failure, err)
			return err
		}

		intermediates.AddCert(fetchedCert)
	}

	if !foundAIA {
		err = fmt.Errorf("No AIA url, and previous error was %s", err)
		self.recordResult(Failure, err)
		return err
	}

	_, err = endEntity.Verify(x509.VerifyOptions{
		DNSName:       self.Hostname,
		Intermediates: intermediates,
		Roots:         self.RootCAList,
	})

	// Return whether or not the verify was successful
	if err == nil {
		// fmt.Println("Success by AIA")
		self.recordResult(SuccessViaAiaFetch, nil)
		return nil
	}

	self.recordResult(Failure, err)
	return err
}

func (self *AiaState) checkAndTryAia(wg *sync.WaitGroup) {
	defer wg.Done()

	dailer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dailer, "tcp", fmt.Sprintf("%s:443", self.Hostname), &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: self.checkCertificate,
	})

	if err == nil {
		// Success would already be recorded
		conn.OCSPResponse()
		conn.Close()
	} else {
		// Make sure we record a failure if we got an error; the sync.Once will protect from dupes
		self.recordResult(Failure, err)
	}
}

type CheckHost struct {
	Hostname string
	Weight   uint64
}

func aggregate(c <-chan *TestResult, quit chan<- bool, progressDisplay *utils.ProgressDisplay, endIdx uint64) {
	var success uint64
	var successW uint64
	var failure uint64
	var failureW uint64
	var successViaAia uint64
	var successViaAiaW uint64

	var results []*TestResult

	for result := range c {
		switch result.Result {
		case Failure:
			failure += 1
			failureW += result.Weight
		case Success:
			success += 1
			successW += result.Weight
		case SuccessViaAiaFetch:
			successViaAia += 1
			successViaAiaW += result.Weight
		}

		results = append(results, result)
		progressDisplay.UpdateProgress("Checking AIA", 0, success+failure+successViaAia, endIdx)
	}

	for _, result := range results {
		if result.Result != Success {
			fmt.Printf("%s %d %s %s\n", result.Hostname, result.Weight, result.Result, result.Error)
		}
	}

	totalCount := float64(success + failure + successViaAia)
	totalWeight := float64(successW + failureW + successViaAiaW)

	fmt.Println("\n\nResults:")
	fmt.Printf("Success Count: %d (%f%%) Weighted Value: %d (%f%%)\n", success, float64(success)/totalCount*100, successW, float64(successW)/totalWeight*100)
	fmt.Printf("Success Via AIA Count: %d (%f%%) Weighted Value: %d (%f%%)\n", successViaAia, float64(successViaAia)/totalCount*100, successViaAiaW, float64(successViaAiaW)/totalWeight*100)
	fmt.Printf("Failure Count: %d (%f%%) Weighted Value: %d (%f%%)\n", failure, float64(failure)/totalCount*100, failureW, float64(failureW)/totalWeight*100)

	quit <- true
}

func processInput(inputChan <-chan *AiaState, wg *sync.WaitGroup) {
	for state := range inputChan {
		state.checkAndTryAia(wg)
	}
}

func main() {
	flag.Parse()

	var hosts []*CheckHost
	if flag.NArg() == 1 {
		hosts = append(hosts, &CheckHost{
			Hostname: flag.Arg(0),
			Weight:   1,
		})
	}

	if len(*hostsFile) > 0 {
		f, err := os.Open(*hostsFile)
		if err != nil {
			log.Fatalf("Could not open hosts file: %s", err)
			return
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), " ")
			weight, err := strconv.ParseUint(parts[1], 10, 64)

			if err != nil {
				log.Printf("Error: Could not parse number of input line %v: %s\n", parts, err)
				continue
			}

			hosts = append(hosts, &CheckHost{
				Hostname: parts[0],
				Weight:   weight,
			})

		}
	}

	if len(hosts) < 1 {
		log.Fatalf("You must specify the host either as the last argument, or via -hosts")
		return
	}

	roots := x509.NewCertPool()
	rootsPEM, err := ioutil.ReadFile(*rootsFile)
	if err != nil {
		panic(err)
	}

	ok := roots.AppendCertsFromPEM([]byte(rootsPEM))
	if !ok {
		panic("Could not load root CAs from " + *rootsFile)
	}

	var progWg sync.WaitGroup
	progressDisplay := utils.NewProgressDisplay()
	progressDisplay.StartDisplay(&progWg)

	completeChan := make(chan bool)
	resultChan := make(chan *TestResult, 4)
	go aggregate(resultChan, completeChan, progressDisplay, uint64(len(hosts)))

	var workWg sync.WaitGroup
	inputChan := make(chan *AiaState, 4)

	for i := 0; i < *numThreads*runtime.NumCPU(); i++ {
		go processInput(inputChan, &workWg)
	}

	for _, hostObj := range hosts {
		workWg.Add(1)
		inputChan <- &AiaState{
			Hostname:   hostObj.Hostname,
			RootCAList: roots,
			ResultChan: resultChan,
			Weight:     hostObj.Weight,
		}
	}

	workWg.Wait()
	close(resultChan)

	// Signal the aggregation function to print output
	<-completeChan

	progressDisplay.Close()
	progWg.Wait()
}
