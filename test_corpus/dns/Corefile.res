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
# ---- dns_depth (dns/dd/): the parent zone (with labdns's DS records) and one zone per target.
# Signed zones are signed on the fly by CoreDNS's dnssec plugin with labdns's throwaway keys.
dd.lab.test:53 {
    file /ddkeys/dd.lab.test.db
}
good.dd.lab.test:53 {
    file /zones/dd/good.db
    dnssec {
        key file /ddkeys/Kgood.dd.lab.test
    }
}
broken.dd.lab.test:53 {
    file /zones/dd/broken.db
    dnssec {
        key file /ddkeys/Kbroken.dd.lab.test
    }
}
unsigned.dd.lab.test:53 {
    file /zones/dd/unsigned.db
}
nocaa.dd.lab.test:53 {
    file /zones/dd/nocaa.db
    dnssec {
        key file /ddkeys/Knocaa.dd.lab.test
    }
}
nosts.dd.lab.test:53 {
    file /zones/dd/nosts.db
    dnssec {
        key file /ddkeys/Knosts.dd.lab.test
    }
}
nomail.dd.lab.test:53 {
    file /zones/dd/nomail.db
    dnssec {
        key file /ddkeys/Knomail.dd.lab.test
    }
}
ststesting.dd.lab.test:53 {
    file /zones/dd/ststesting.db
    dnssec {
        key file /ddkeys/Kststesting.dd.lab.test
    }
}
stsbroken.dd.lab.test:53 {
    file /zones/dd/stsbroken.db
    dnssec {
        key file /ddkeys/Kstsbroken.dd.lab.test
    }
}
stsmismatch.dd.lab.test:53 {
    file /zones/dd/stsmismatch.db
    dnssec {
        key file /ddkeys/Kstsmismatch.dd.lab.test
    }
}
notlsrpt.dd.lab.test:53 {
    file /zones/dd/notlsrpt.db
    dnssec {
        key file /ddkeys/Knotlsrpt.dd.lab.test
    }
}
dkim1024.dd.lab.test:53 {
    file /zones/dd/dkim1024.db
    dnssec {
        key file /ddkeys/Kdkim1024.dd.lab.test
    }
}
dkim512.dd.lab.test:53 {
    file /zones/dd/dkim512.db
    dnssec {
        key file /ddkeys/Kdkim512.dd.lab.test
    }
}
# lab.test itself answers a definite "no CAA" (so the CAA climb of the dd targets ends there);
# every other name still goes to Docker's resolver. Not a "lab.test:53" block: CoreDNS routes a
# DS query to the HIGHEST enclosing zone it serves, which would then hide dd.lab.test's DS records.
.:53 {
    template IN CAA lab.test {
        match "^lab[.]test[.]$"
        rcode NOERROR
        fallthrough
    }
    forward . 127.0.0.11
}
