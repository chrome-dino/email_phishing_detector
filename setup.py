from setuptools import setup, find_packages

setup(
    name = "email_phishing_detector",
    py_modules=['email_phishing_detector'],
    packages=find_packages(where='src'),
    package_dir={'':'src'},
)