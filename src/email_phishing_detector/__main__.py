import argparse
import email_phishing_detector
import sys

def main():
    parser = argparse.ArgumentParser()

    # cmd line args
    
    parser.add_argument("-f", "--file", help="path to email file",required=True)
    parser.add_argument("-k", "--key", help="virus total api key",required=True)
    parser.add_argument("-p", "--password", help="password for url shortening service",required=False)
    parser.add_argument("-m", "--mode", help="Name of url shortening service. Must be one of: bitly or tinyurl", required=True)

    args = parser.parse_args()

    if args.mode not in ['bitly', 'tinyurl']:
        print('Error: mode must be one of: bitly, tinyurl')
        exit(-1)
    
    scan = email_phishing_detector.EmailPhishingDetector(file=args.file, password=args.password, key=args.key, mode=args.mode)
    scan.run()
    
if __name__ == "__main__":
    main()