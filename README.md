# Analyze how many hosts in a list require AIA fetching to load

Requires Go 1.8

## Usage

```
curl https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt -o certdata.txt
go get github.com/agl/extract-nss-root-certs
extract-nss-root-certs > certdata.pems

go get github.com/jcjones/aia-chaser/cmd/verify-aia
verify-aia -roots certdata.pems incomplete-chain.badssl.com
```

## Examples

```
verify-aia -roots certdata.pems incomplete-chain.badssl.com
verify-aia -roots certdata.pems self-signed.badssl.com
verify-aia -roots certdata.pems -hosts hostlist.example
```

## Host List Input Format
`Hostname` `Weight value`

```
example.com 100
incomplete-chain.badssl.com 10
self-signed.badssl.com 1
```
(See [hostlist.example](hostlist.example))

## Output
```
<Errors, if any>

Results:
Success Count: 1 (33.333333%) Weighted Value: 100 (90.090090%)
Success Via AIA Count: 1 (33.333333%) Weighted Value: 10 (9.009009%)
Failure Count: 1 (33.333333%) Weighted Value: 1 (0.900901%)
```

The absolute counts are first, followed by the weighted counts. The weighting values come
from the input file.
