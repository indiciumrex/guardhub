# dns-res: the scanner's recursive resolver in the lab (SCANNER_DNS_SERVER). It answers the
# lab zones itself and passes every other name to Docker's resolver. It is NOT the
# nameserver of any zone, so it never appears in an open-resolver test.
# For subdomain_takeover it also serves st.lab.test and stand-ins of provider zones
# (provider-live.db: every name exists; provider-gone.db: no name exists). They are visible
# only on the lab network, which has no internet.
_dmarc.lab.test:53 {
    file /zones/lab-dmarc.db
}
dns.lab.test:53 {
    file /zones/dns.lab.test.db
}
axfr.dns.lab.test:53 {
    file /zones/axfr.db
}
openres.dns.lab.test:53 {
    file /zones/openres.db
}
st.lab.test:53 {
    file /zones/st.lab.test.db
}
s3.amazonaws.com:53 s3-website-eu-west-1.amazonaws.com:53 bitbucket.io:53 surge.sh:53 github.io:53 elasticbeanstalk.com:53 pages-host.test:53 {
    file /zones/provider-live.db
}
azurewebsites.net:53 gone-cdn.test:53 {
    file /zones/provider-gone.db
}
.:53 {
    forward . 127.0.0.11
}
