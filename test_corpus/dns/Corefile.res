# dns-res: the scanner's recursive resolver in the lab (SCANNER_DNS_SERVER). It answers the
# lab zones itself and passes every other name to Docker's resolver. It is NOT the
# nameserver of any zone, so it never appears in an open-resolver test.
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
.:53 {
    forward . 127.0.0.11
}
