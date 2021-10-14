# snyksearch

Snyksearch searches for vulnerable application versions.

## Description

Snyksearch is a simple vulnerability search program from command line. It searches for vulnerable versions using snyk using BeautifulSoup and requests. It's completely written in Python.

snyk: https://snyk.io/

## Getting Started

### Installation
Python version 3.0 - 3.10
```
git clone https://github.com/TralseDev/snyksearch.git
pip3 install -r requirements.txt
```

### Executing program
```
python3 main.py
```

### Examples:

```
python3 main.py --search phpmyadmin --type alpine --link 
```

## Help

```
python3 main.py -h
```

## Authors

Tralse

## Version History

* 1.0 (14.10.2021)
    * Stable version

## License

This project is licensed under the GNU General Public License v3.0 (GNU GPLv3 License).
License also contains copy-right notices and licenses of both libraries: requests and prettytable