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
usage: __main__.py [-h] -db HOSTNAME -u USERNAME -p PASSWORD [-port PORT] [-s SCHEMA] [-t TABLE] [-a | --admin | --no-admin]
                   [-v | --verbose | --no-verbose]

options:
  -h, --help            show this help message and exit
  -db HOSTNAME, --hostname HOSTNAME
                        IP address or hostname of the target database
  -u USERNAME, --username USERNAME
                        Login username
  -p PASSWORD, --password PASSWORD
                        Login Password
  -port PORT, --port PORT
                        Port number (Defaults to 3306)
  -s SCHEMA, --schema SCHEMA
                        Name of the schema to be used in table extraction mode. Requires the table option
  -t TABLE, --table TABLE
                        Name of the table to be used in table extraction mode. Requires the schema option
  -a, --admin, --no-admin
                        Enable admin mode to extract database user info. Requires admin credentials
  -v, --verbose, --no-verbose
                        List additional details in the user report
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
