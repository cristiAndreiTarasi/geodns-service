FROM debian:bullseye

# Install dependencies
RUN apt-get update && apt-get install -y \
    pdns-server \
    pdns-backend-geoip \
    pdns-backend-pipe \
    python3 \
    python3-pip \
    git \
    curl \
    rsync \
    build-essential \
    libtool \
    pkg-config \
    automake \
    autoconf && \
    apt-get clean

# Install Python GeoIP library
RUN pip3 install maxminddb

# Install the pdns-remotebackend-python package
RUN git clone https://github.com/PowerDNS/pdns-remotebackend-python.git /usr/local/pdns_remotebackend
RUN pip3 install /usr/local/pdns_remotebackend geoip2 pycountry

# Copy the GeoIP Python backend script into the container
COPY ./geo_dns_backend/backend.py /usr/local/bin/backend.py

COPY ./geo_dns_backend/DNS_mappings.json /var/lib/pdns/DNS_mappings.json

# Set executable permissions for the script
RUN chmod +x /usr/local/bin/backend.py

# Create necessary directories for DNSSEC keys
RUN mkdir -p /dnssec && chmod 755 /dnssec

# Copy configuration files
COPY ./pdns.conf /etc/powerdns/pdns.conf
COPY ./MaxMind/GeoLite2-City.mmdb /etc/powerdns/GeoLite2-City.mmdb

# Ensure correct permissions
RUN chmod 644 /etc/powerdns/GeoLite2-City.mmdb

# Expose PowerDNS ports
EXPOSE 53/udp
EXPOSE 53/tcp

# Start PowerDNS
CMD ["pdns_server"]
