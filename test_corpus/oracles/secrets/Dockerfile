# js_secrets ground truth (oracle_secrets.py): gitleaks v8.21.2 (the same release CI's secret scan
# uses), run unmodified with its default rules on the home page and its same-origin scripts.
FROM zricethezav/gitleaks:v8.21.2 AS gitleaks
FROM python:3.12-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
RUN apk add --no-cache curl
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/gitleaks
WORKDIR /o
COPY oracle_secrets.py ./
ENTRYPOINT ["python3", "/o/oracle_secrets.py"]
