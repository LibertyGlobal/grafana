FROM centos:6

RUN yum install -y initscripts curl tar gcc libc6-dev git epel-release
RUN yum install -y nodejs golang

RUN mkdir -p /go/src /go/bin && chmod -R 777 /go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

WORKDIR /go/src/github.com/grafana/grafana

CMD ["go", "run", "build.go", "build"]
