# dns_depth ground truth (oracle_dns.py): BIND's dig and delv, OpenSSL and curl, run unmodified.
FROM python:3.12-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
RUN apk add --no-cache bind-tools curl openssl && pip install --no-cache-dir pyyaml==6.0.2
WORKDIR /o
COPY oracle_dns.py ./
ENTRYPOINT ["python3", "/o/oracle_dns.py"]
