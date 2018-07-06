FROM centos:6.7

# prepare
RUN yum clean all && yum -y install yum-plugin-ovl
RUN yum -y install ca-certificates curl tar gunzip
RUN update-ca-trust force-enable

# install golang
RUN curl -L https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz -o /root/go.tar.gz
RUN tar -C /usr/local -vxzf /root/go.tar.gz

# build
ENV PATH="/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    GOPATH="/go" \
    GOROOT="/usr/local/go"

RUN yum -y install nss openssl git gcc

WORKDIR /go/src/github.com/grafana/grafana
COPY . .
RUN go run build.go setup
RUN go run build.go build
