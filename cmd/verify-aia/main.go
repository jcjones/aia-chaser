/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
  "crypto/tls"
  "crypto/x509"
  "encoding/asn1"
  "flag"
  "fmt"
  "net/http"
  "io/ioutil"
  "log"
)

var rootsFile = flag.String("roots", "roots.pem", "Trusted root CAs in PEM format")

var authorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
var aiaOCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
var aiaIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

func decodeCert(cert *x509.Certificate) string {
  return fmt.Sprintf("%+v %+v", cert.Subject, cert.Extensions)
}

func decodeAIA(ext []byte) (string, error) {
  var seq asn1.RawValue
  rest, err := asn1.Unmarshal(ext, &seq)
  if err != nil {
    return "", fmt.Errorf("Error unmarshaling %s", err)
  } else if len(rest) != 0 {
    return "", fmt.Errorf("x509: trailing data after X.509 extension")
  }

  if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
    return "", asn1.StructuralError{Msg: "bad SAN sequence"}
  }

  rest = seq.Bytes

  for ; len(rest) > 0; {
    var inside asn1.RawValue
    rest, err = asn1.Unmarshal(rest, &inside)
    if err != nil {
      return "", fmt.Errorf("Error unmarshaling %s", err)
    }

    if !inside.IsCompound || inside.Tag != 16 || inside.Class != 0 {
      return "", asn1.StructuralError{Msg: "bad SAN sequence"}
    }

    var oidValue asn1.ObjectIdentifier
    body, err := asn1.Unmarshal(inside.Bytes, &oidValue)
    if err != nil {
      return "", fmt.Errorf("Error unmarshaling %s", err)
    }

    var extensionData asn1.RawValue
    rest, err := asn1.Unmarshal(body, &extensionData)
    if err != nil {
      return "", fmt.Errorf("Error unmarshaling %s", err)
    } else if len(rest) != 0 {
      return "", fmt.Errorf("x509: trailing data after AIA extension")
    }

    if oidValue.Equal(aiaIssuer) {
      switch extensionData.Tag {
        case 6:
          return string(extensionData.Bytes), nil
        default:
          return "", fmt.Errorf("Unknown type for AIA Issuer extension: %+v", extensionData)
      }
    }

  }

  // No AIA Issuer extension values
  return "", nil
}

type AiaState struct {
  Hostname string
  RootCAList *x509.CertPool
}

func (self *AiaState) checkCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
  var endEntity *x509.Certificate
  intermediates := x509.NewCertPool()

  for _, certAsn1 := range rawCerts {
    cert, err := x509.ParseCertificate(certAsn1)
    if err != nil {
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
    DNSName: self.Hostname,
    Intermediates: intermediates,
    Roots:   self.RootCAList,
  })

  if err == nil {
    // Didn't need AIA fetching, so we are done
    fmt.Println("Success")
    return nil
  }

  // If not, let's find an AIA extension
  var aiaURL *string

  for _, ext := range endEntity.Extensions {
    if ext.Id.Equal(authorityInfoAccess) {
      url, err := decodeAIA(ext.Value)
      if err != nil {
        return err
      }

      if len(url) > 0 {
        aiaURL = &url
      }
    }
  }

  if aiaURL == nil {
    return fmt.Errorf("No AIA url, and previous error was %s", err)
  }

  // Fetch AIA
  fmt.Printf("Fetching AIA: %s\n", *aiaURL)

  response, err := http.Get(*aiaURL)
  if err != nil {
    return err
  }

  defer response.Body.Close()
  certBytes, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return err
  }

  fetchedCert, err := x509.ParseCertificate(certBytes)
  if err != nil {
    return err
  }

  intermediates.AddCert(fetchedCert)
  _, err = endEntity.Verify(x509.VerifyOptions{
    DNSName: self.Hostname,
    Intermediates: intermediates,
    Roots:   self.RootCAList,
  })

  // Return whether or not the verify was successful
  if err == nil {
    fmt.Println("Success by AIA")
  }
  return err
}

func main() {
  flag.Parse()
  if flag.NArg() != 1 {
    log.Fatalf("You must specify the host")
    return
  }

  hostname := flag.Arg(0)

  aiaCheck := &AiaState{
    Hostname: hostname,
    RootCAList: x509.NewCertPool(),
  }

  rootsPEM, err := ioutil.ReadFile(*rootsFile)
  if err != nil {
    panic(err)
  }

  ok := aiaCheck.RootCAList.AppendCertsFromPEM([]byte(rootsPEM))
  if !ok {
    panic("Could not load root CAs from " + *rootsFile)
  }

  conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", hostname), &tls.Config{
    InsecureSkipVerify: true,
    VerifyPeerCertificate: aiaCheck.checkCertificate,
  })
  if err != nil {
    fmt.Println("Error: ", err)
    return
  }
  defer conn.Close()

  // state := conn.ConnectionState()
  // log.Printf("State: %+v", state)
}