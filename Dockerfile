FROM golang:1.22-bookworm AS tools
RUN go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM python:3.11-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tools /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=tools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /go/bin/subfinder /usr/local/bin/subfinder
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "main.py"]
