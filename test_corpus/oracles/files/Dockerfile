# exposed_files ground truth (oracle_files.py): curl and libmagic (`file`), run unmodified.
FROM python:3.12-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
RUN apk add --no-cache curl file
WORKDIR /o
COPY oracle_files.py ./
ENTRYPOINT ["python3", "/o/oracle_files.py"]
