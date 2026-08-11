"""Common ports for scanning (Module 2)."""

COMMON_PORTS = [
    21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,
    587,993,995,1433,1521,2049,2181,2375,2376,3000,3306,3389,
    5432,5601,5900,5984,6379,6443,7001,7002,8000,8001,8008,8009,
    8080,8081,8443,8888,9000,9090,9092,9200,9300,9418,11211,27017,50070,
]

# Ports that often run unauthenticated services
HIGH_RISK_PORTS = {
    6379: "Redis (often unauth)",
    27017: "MongoDB (often unauth)",
    9200: "Elasticsearch (often unauth)",
    2375: "Docker API (RCE potential)",
    5900: "VNC",
    11211: "Memcached",
}
