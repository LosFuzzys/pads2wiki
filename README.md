# pads2wiki

script to import ctfpads into mediawiki

## Installation

Use python3 or be prepared to experience unicode errors...

```
mkvirtualenv -p `which python3` pads2wiki
workon pads2wiki
pip install 'git+https://github.com/LosFuzzys/pads2wiki.git'
```

or for local hacking use

```
git clone 'https://github.com/LosFuzzys/pads2wiki.git'
cd pads2wiki
pip install -e .
```

## Usage

```
usage: pads2wiki [-h] [--wiki-url WIKI_URL] [--wiki-user WIKI_USER]
                 [--wiki-password WIKI_PASSWORD]
                 [--ctfpad-apikey CTFPAD_APIKEY] [--ctfpad-url CTFPAD_URL]
                 [-c CONFIG] [--overwrite]
                 [--imported-ctf-list IMPORTED_CTF_LIST] [--logfile LOGFILE]
                 [-q] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --overwrite           Overwrite the contents of an existing wiki page
  --imported-ctf-list IMPORTED_CTF_LIST
                        path to json file containing already import ctfs
  --logfile LOGFILE     Log output of this script to this file
  -q, --quiet           Surpress console log output
  -v, --verbose         enable debug log

credentials:
  --wiki-url WIKI_URL   URL to mediawiki
  --wiki-user WIKI_USER
                        mediawiki username
  --wiki-password WIKI_PASSWORD
                        mediawiki password
  --ctfpad-apikey CTFPAD_APIKEY
                        API key of ctfpad user
  --ctfpad-url CTFPAD_URL
                        URL to ctfpad
  -c CONFIG, --config CONFIG
                        ini style config file. if not given all other
                        credential options must be set.
```

You can put the following options in the config file and optionally override
them on the command line.

```ini
[wiki]
url = https://example.com/wiki
user = username
password = super+secret+password

[ctfpad]
url = https://example.com:1337
apikey = api_token_you_got_from_ctfpad
```

Then you can start the import with

```
pads2wiki -c example.ini
```
