# email_phishing_detector 

Email_phishing_detector is a tool that can be used to determine the trustworthiness of an email. The main purpose of the tool is to get around the difficulties of evaluating the legitimacy of shortened urls within emails by reaching out the url shortening services via API and returning the original URLs. This tool automatically extracts link from an email and expands them if necessary. It then submits all links to virus total in order to help make a final determination on whether or not the email is a phishing attempt.


## Table of Contents
* <a href="#key-features">Key Features</a></br>
* <a href="#installation">Installation</a></br>
* <a href="#how-to-use">How To Use</a> </br>
* <a href="#notes">Notes</a></br>
* <a href="#license">License</a>


## Key Features

* Automatically extract links from an email
* Takes shortened URLs and expands them into their original form
* Compatible with multiple URL shortening services including bitly and tiny url  
* Submits links to virus total and builds a report


## Installation

```bash
# Clone this repository
$ git clone https://github.com/chrome-dino/email_phishing_detector.git

# From the directory containing your git projects
$ pip install -e email_phishing_detector
```

Uses the following python libraries:
* pyshorteners
* virustotal_python
* setuptools
* base64
* argparse
* sys


## How To Use

### Help Menu

```bash
usage: __main__.py [-h] -f FILE -k KEY [-p PASSWORD] -m MODE

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  path to email file
  -k KEY, --key KEY     virus total api key
  -p PASSWORD, --password PASSWORD
                        password for url shortening service
  -m MODE, --mode MODE  Name of url shortening service. Must be one of: bitly or tinyurl
```

### Video
* https://youtu.be/ENCz8EvVfuc

### Examples

```bash
# run the report generator with a standard user
$ py -m mysql_enumerator -db hostname -u user -p password

# run the report generator with elevated permissions and extract info on database users
$ py -m mysql_enumerator -db hostname -u root -p password -a

# extract the rows from a table
$ py -m mysql_enumerator -db hostname -u user -p password -s schema_name -t table_name1,table_name2
```


## Notes

* Tested on python 3.10.4


## License

MIT
