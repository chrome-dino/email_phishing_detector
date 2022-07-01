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
* https://youtu.be/-LcXm3Uu4Yo

### Examples

```bash
# Scan urls and attachments for the input email file. Supply a vt api key with the k flag
$ py -m email_phishing_detector -m tinyurl -f  EMAIL_FILE -k API_KEY

# some services, like bitly, require a password. Use the p flag for these cases
$ py -m email_phishing_detector -m bitly -f  EMAIL_FILE -k API_KEY -p PASSWORD
```


## Notes

* Tested on python 3.10.4


## License

MIT
