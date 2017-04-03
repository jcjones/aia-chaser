# Check whether AIA fetching is necessary for a host

Requires Go 1.8

## Usage

```
curl https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt -o certdata.txt
go get github.com/agl/extract-nss-root-certs
extract-nss-root-certs > certdata.pems

go get github.com/jcjones/aia-chasercmd/verify-aia
verify-aia -roots certdata.pems incomplete-chain.badssl.com
```

## Examples

```
verify-aia -roots certdata.pems incomplete-chain.badssl.com
verify-aia -roots certdata.pems self-signed.badssl.com
verify-aia -roots certdata.pems badssl.com
```

## Output

### On Failure

```
Error:  No AIA url, and previous error was x509: certificate signed by unknown authority
```

### On Success without AIA

```
Success
```

### On Success using AIA

```
Fetching AIA: http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt
Success by AIA
```