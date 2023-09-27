# syntax=docker/dockerfile:1

FROM golang:1.21

WORKDIR /btcd-build

RUN git clone https://github.com/halseth/btcd.git
WORKDIR /btcd-build/btcd
RUN git checkout matt
RUN go install -v

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY . ./

RUN ls

RUN ls -la /app

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -v -o scenario ./cmd/scenario

RUN ls -la /
RUN ls -la /app
RUN ls

# Run
RUN cat correct_trace.txt
CMD ["./run_correct.sh"]