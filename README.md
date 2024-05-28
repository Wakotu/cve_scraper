# Web Scraper to collect cve information

## Usage

```bash
python main.py -h
usage: main.py [-h] [-d] [-n] [-o]

CVE Scraper

options:
  -h, --help      show this help message and exit
  -d, --debug     debug mode
  -n, --nvd       fetch from nvd or mitre website
  -o, --overview  get overview report
```

You could run `main.py` without arguments directly.

The scraper will wait for you to enter the `query` keyword and collect corresponding CVEs automatically.
