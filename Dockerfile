##################################################################
FROM ubuntu:22.04 AS build_stage
WORKDIR /dropwatch

RUN apt update \
  && apt install -y \
  build-essential \
  autoconf \
  libnl-3-dev \
  libnl-genl-3-dev \
  libpcap-dev \
  libreadline-dev \
  binutils-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY . .

RUN ./autogen.sh
RUN ./configure
RUN make

##################################################################
FROM ubuntu:22.04 AS run_stage
WORKDIR /dropwatch

RUN apt update \
  && apt install -y \
  libnl-3-200 \
  libnl-genl-3-200 \
  libpcap0.8 \
  libreadline8 \
  binutils \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build_stage /dropwatch/src/dropwatch /dropwatch/dropwatch

CMD /dropwatch/dropwatch