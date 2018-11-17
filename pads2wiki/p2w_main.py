#!/usr/bin/env python3

# Copyright 2016 LosFuzzys. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import configparser
import json
import sys
import tempfile
from urllib.parse import urlparse

import mwclient

import pypandoc

from .padclient import CTFPadClient
from .setup_logging import setup_logging

# from lxml import etree
# we don't parse html output of the pad for now, since it seems to be broken
# anyway. we assume that there is github markdown in the pads and use pandoc
# to convert it to mw syntax.
etree = None

OVERWRITE_ALL = False
OVERWRITE_CTFS = ['training']

SOURCE_FILE_EXTENSIONS = {'py': 'python',
                          'rb': 'ruby',
                          'c': 'c',
                          'h': 'c++',
                          'cpp': 'c++',
                          'cc': 'c++',
                          'hpp': 'c++',
                          'php': 'php',
                          'php5': 'php',
                          'pl': 'perl',
                          'js': 'javascript',
                          'jsp': 'jsp',
                          'rs': 'rust',
                          'go': 'go',
                          'hs': 'haskell',
                          'cl': 'lisp',
                          'coffee': 'coffeescript',
                          'html': 'html',
                          'xml': 'xml',
                          'json': 'json',
                          'sh': 'bash',
                          'bash': 'bash',
                          'S': 'asm',
                          's': 'asm',
                          'll': 'llvm',
                          'scm': 'scheme',
                          'java': 'java',
                          'scala': 'scala',
                          'clojure': 'clojure',
                          'cs': 'csharp',
                          }
IMAGE_FILE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif']
# CTF Categories coming from the pads are lower()ed before the lookup
# in this map.
CTF_CATEGORY_MAP = {'code': 'misc',
                    'crypto': 'crypto',
                    'cryptography': 'crypto',
                    'exploit': 'pwn',
                    'exploiting': 'pwn',
                    'exploitation': 'pwn',
                    'pwn': 'pwn',
                    'pwning': 'pwn',
                    'rev': 'reversing',
                    'reverse': 'reversing',
                    'reversing': 'reversing',
                    'crack me': 'reversing',
                    'crackme': 'reversing',
                    'revcrypt': 'reversing',
                    'web': 'web',
                    'forensics': 'forensics',
                    'forensic': 'forensics',
                    'infoforensic': 'forensics',
                    'misc': 'misc',
                    'trivia': 'misc',
                    'programming': 'misc',
                    'network': 'misc',
                    'admin': 'misc',
                    'pizza': 'pizza',
                    'food': 'pizza'
                    }
CTF_CATEGORY_DEFAULT = 'Uncategorized'
# CTF_BLACKLIST = ['meta', "training"]
CTF_BLACKLIST = ['meta']

UPLOAD_IMAGES_TO_WIKI = False
MAX_SOURCE_LINES = 700

# TODO: this is not a complete list, update as things fail
MW_PAGETITLE_FORBIDDEN_CHARS = ['[', "]", "\n", "\r"]

ALREADY_IMPORTED_CTFS = []

# global vars initialized in init function
log = None
cl = None
site = None


def load_imported_ctfs_from(path="./imported-ctfs.json"):
    try:
        log.debug("reading from '%s'", path)
        with open(path) as f:
            global ALREADY_IMPORTED_CTFS
            ALREADY_IMPORTED_CTFS = json.load(f)
    except:
        log.exception("failed to read from '%s'", path)


def dump_imported_ctfs_to(path="./imported-ctfs.json"):
    try:
        log.debug("writing to '%s'", path)
        with open(path, "w") as f:
            json.dump(ALREADY_IMPORTED_CTFS, f)
    except:
        log.exception("failed to write to '%s'", path)


def clean_trailing_whitespace(content):
    l = []
    for line in content.splitlines():
        l.append(line.rstrip())
    return "\n".join(l)


def replace_a_with_mw(tree):
    for a in tree.xpath("//a"):
        if a.text and a.text.strip():
            mwa = "[{} {}]".format(a.attrib['href'], a.text)
        else:
            mwa = "[{} {}]".format(a.attrib['href'], a.attrib['href'])
        s = etree.Element("span")
        s.text = mwa
        s.attrib['class'] = 'plainlinks'
        tree.replace(a, s)


def replace_indent(content):
    return content.replace("&#160;", " ").replace("&nbsp;", " ")


def sanitize_html_pad(content):
    parser = etree.HTMLParser()
    html = etree.fromstring(content, parser=parser)
    body = html.xpath("/html/body")[0]
    replace_a_with_mw(body)
    newcontent = ""
    if body.text:
        newcontent += body.text.strip()
    for c in body:
        if c.tag == "br":
            newcontent += "<br/>\n"
            if c.tail:
                newcontent += c.tail
        else:
            newcontent += etree.tostring(c, pretty_print=True, method="html")
    newcontent = replace_indent(newcontent)
    newcontent = clean_trailing_whitespace(newcontent)
    return newcontent


def sanitize_mw_pagetitle(title):
    for c in MW_PAGETITLE_FORBIDDEN_CHARS:
        title = title.replace(c, " ")
    return title


def prepare_plain_text_pad(pad):
    if "Welcome to Etherpad!" in pad \
            and "Get involved with Etherpad" in pad:
        log.warning("detected default pad content -- ignoring pad")
        return ""
    log.debug("converting pad content:\n'''\n" + pad + "\n'''")
    pad = pypandoc.convert_text(pad, "mediawiki", format="markdown_github")
    log.debug("converted pad content:\n'''\n" + pad + "\n'''")
    return pad


def format_page_title(ctf, chal):
    pagetitle = "{} {} - {} ({})"\
                .format(chal['category'], chal['points'], chal['title'],
                        ctf['name'])
    pagetitle = sanitize_mw_pagetitle(pagetitle)
    return pagetitle


def format_challenge_link(pagetitle, chal):
    return "[[{}|{} ({} {})]]".format(pagetitle, chal['title'],
                                      chal['category'], chal['points'])


def create_ctf_page(ctf, challenges):

    ctfid = ctf['id']
    pad = cl.ctf_pad_text(ctfid)

    if 'error' in pad:
        log.warning("failed to get ctf pad: '{}'"
                    .format(pad['error']))
        return

    ctfpad = pad['text']

    pagetitle = "Category:" + ctf['name']
    p = site.Pages[pagetitle]
    t = "[[Category:CTFs]]\n"
    t += "CTF meta pad content imported here:\n\n"

    should_save = False
    if not p.exists:
        should_save = True
    else:
        if OVERWRITE_ALL or ctf['name'] in OVERWRITE_CTFS:
            should_save = True
            log.info("overwriting existing page '{}'".format(p.name))

    if should_save:
        content = t + prepare_plain_text_pad(ctfpad)
        p.save(content)
    return site.Pages[pagetitle]


def add_challenge_link(page, title, chal):
    t = page.text()
    t += "\n* " + format_challenge_link(title, chal)
    page.save(t)


def format_chal_meta(chal):
    chal = chal.copy()
    chal['assigned'] = ", ".join("[[User:{u}|{u}]]".format(u=u)
                                 for u in chal['assigned'])
    return """
{{{{Infobox ChallengeMeta
 |title={title}
 |points={points}
 |assigned={assigned}
 |done={done}
 |category={category}
}}}}
""".format(**chal)


def sanitize_pagetitle_for_mediawiki(title):
    # https://www.mediawiki.org/wiki/Manual:Page_title
    # remove # < > [ ] | { } _
    for ch in '# < > [ ] | { } _'.split(' '):
        if ch in title:
            title = title.replace(ch, '')
    return title


def create_challenge_page(ctf, ctfpage, chal, chalid):

    # chalpadh = cl.challenge_pad_html(chalid)['html']
    chalpad = cl.challenge_pad_text(chalid)
    log.debug(chalpad)
    if "error" in chalpad:
        log.warning("failed to get challenge pad: '{}'"
                    .format(chalpad['error']))
        if chal['filecount'] == 0:
            return None
        else:
            log.debug("empty page with files for id={}".format(chalid))
            chalpad['text'] = ''

    chalpadt = chalpad['text']

    pagetitle = format_page_title(ctf, chal)

    pagetitle = sanitize_pagetitle_for_mediawiki(pagetitle)

    summary = "{} ctfpad content (created by pads2wiki)"\
              .format(pagetitle)

    log.info('retrieving page: {}'.format(pagetitle))

    p = site.Pages[pagetitle]

    should_save = False
    if not p.exists:
        should_save = True
    else:
        if OVERWRITE_ALL or ctf['name'] in OVERWRITE_CTFS:
            should_save = True
            log.info("overwriting existing page '{}'".format(p.name))

    if should_save:
        log.info("overwriting existing page '{}'".format(p.name))
    else:
        log.info("page with title exists: '{}'".format(pagetitle))
        return p

    log.info("Creating page with title: '{}'".format(pagetitle))

    content = prepare_plain_text_pad(chalpadt)

    mwcontent = ""
    mwcontent += "[[Category:{}]]\n".format(ctf['name'])
    ctfcat = CTF_CATEGORY_MAP.get(chal['category'].lower(),
                                  CTF_CATEGORY_DEFAULT)
    mwcontent += "[[Category:{}]]\n".format(ctfcat)
    if chal['done']:
        mwcontent += "[[Category:Solved Task]]\n"
    else:
        mwcontent += "[[Category:Unsolved Task]]\n"
    mwcontent += format_chal_meta(chal)
    mwcontent += "\n"
    mwcontent += content
    # log.debug("Saving challenge with content\n'''\n" + mwcontent + "\n'''")
    p.save(mwcontent, summary=summary)
    return site.Pages[pagetitle]


def create_ctf_category_pages(categories):
    log.info("creating pages for the CTF categories")
    p = site.Pages['Category:Task Categories']
    if not p.exists:
        p.save("Categories of challenges")

    for cat in categories + [CTF_CATEGORY_DEFAULT]:
        p = site.Pages["Category:" + cat]
        if not p.exists:
            log.info("creating new category {}".format(cat))
            p.save("[[Category:Task Categories]]")


def attach_file_to_page(chal, ctf, chalpage, chalid):
    log.info("Found {} attached files for '{}'"
             .format(chal['filecount'], chal['title']))

    files = cl.challenge_files(chalid)["files"]
    t = chalpage.text()
    t = t + "\n\n== Attached Files ==\n\n"
    for cf in files:
        log.info("processing file '{}'".format(cf['name']))
        url = "{}{}".format(cl.remote.strip("/"), cf['path'])
        # mediawiki style link directly to the pad
        linktopad = "[{} {}]".format(url, cf['name'])
        # code for uploading to mediawiki
        newname = "{}-{}".format(cf['id'], cf['name'])
        desc = "file for challenge {} ({}) uploaded by {}"\
               .format(chal['title'], ctf['name'], cf['user'])

        t += "* " + linktopad + "\n"

        ext = cf['name'].split(".")[-1]
        if ext in SOURCE_FILE_EXTENSIONS:
            try:
                filecontent = cl.file_content(cf)
                for codec in ("utf-8", "ascii", "iso8859_15",
                              "iso8859_2", "utf-16", "utf-32"):
                    try:
                        filecontent = filecontent.decode(codec)
                        break
                    except Exception as e:
                        s = ("failed to decode filecontent"
                             " of {} as {}: {}"
                             .format(cf['name'], codec, e))
                        log.warning(s)
                else:
                    log.warning("failed to decode filecontent of {}"
                                .format(cf['name']))
                    filecontent = "ERROR: failed to import"

                linecount = filecontent.count("\n")
                if linecount > MAX_SOURCE_LINES:
                    lines = filecontent.split("\n")
                    filecontent = "\n".join(lines[:MAX_SOURCE_LINES])
                    filecontent += "\n\n[...]\n\n"
                    filecontent += ("WARNING: truncated file because it"
                                    " exceeds the maximum display size!")
                    log.warning("truncating file '{}' to {} lines from {}"
                                .format(cf['name'], MAX_SOURCE_LINES,
                                        linecount))
                s = "<syntaxhighlight lang={}>\n"
                s += "{}\n"
                s += "</syntaxhighlight>\n"
                s = s.format(SOURCE_FILE_EXTENSIONS[ext],
                             filecontent)
                t += "\n" + s + "\n"
            except Exception:
                log.warning("unkown error during processing of file '{}'"
                            .format(cf['name']),
                            exc_info=sys.exc_info())

        # if image file, then display image in the wiki
        # FIXME: the wiki rejects nearly all uploads because of a
        # mimetype mismatch...
        if ext in IMAGE_FILE_EXTENSIONS:
            is_uploaded = False
            if UPLOAD_IMAGES_TO_WIKI:
                try:
                    site.upload(url, newname, desc)
                    is_uploaded = True
                except Exception as e:
                    log.info("mediawiki couldn't fetch url '{}' because {}"
                             .format(url, e))
                    suffix = newname.split(".")[-1]
                    tempf = tempfile.NamedTemporaryFile("w+b", suffix=suffix)
                    try:
                        filecontent = cl.file_content(cf)
                        tempf.write(filecontent)
                        tempf.flush()
                        tempf.seek(0)
                        site.upload(tempf, newname, desc)
                        log.info("uploaded image to {}".format(newname))
                        is_uploaded = True
                    except Exception as e:
                        log.info("couldn't upload url '{}' because {}"
                                 .format(url, e))
                    finally:
                        tempf.close()

            if is_uploaded:
                img = site.Images[newname]
                if img.exists:
                    log.info("Adding image")
                    t += "[[File:{}]]\n".format(newname)
            else:
                # https://www.mediawiki.org/wiki/Manual:$wgAllowExternalImages
                t += url + "\n"

    log.debug("saving new attached content with length {}".format(len(t)))
    chalpage.save(t)


def import_challenge_pad(chal, ctf, ctfpage):
    log.debug(chal)
    log.info("Processing challenge '{}' (id={})"
             .format(chal['title'], chal['id']))
    chalid = chal['id']
    chal = cl.challenge(chalid)['challenge']
    log.debug(chal)

    chalpage = create_challenge_page(ctf, ctfpage, chal, chalid)

    if chalpage:
        if "Attached Files" in chalpage.text():
            log.info("skipping attached files for '{}'"
                     .format(chalpage.name))
        elif chal['filecount'] > 0:
            attach_file_to_page(chal, ctf, chalpage, chalid)
    else:
        log.warning("processing of challenge '{}' (id={}) failed"
                    .format(chal['title'], chal['id']))


def import_ctf_pads():
    for ctf in cl.ctfs()['ctfs']:
        ctfid = ctf['id']
        ctfname = ctf['name']
        if ctfname in ALREADY_IMPORTED_CTFS:
            log.info("skipping ctf %s because it's in already imported list",
                     ctfname)
            continue

        log.info("Processing CTF '{}' id={}".format(ctfname, ctfid))
        # for testing
        # if ctfname != "testCTF":
        #     continue

        if ctfname in CTF_BLACKLIST or ctfname.lower() in CTF_BLACKLIST:
            log.info("skipping blacklisted ctf '{}'".format(ctfname))
            continue

        chals = cl.challenges(ctfid)['challenges']
        log.info("got {} challenges".format(len(chals)))

        ctfpage = create_ctf_page(ctf, chals)
        if not ctfpage:
            log.warning('No ctfpage for {}, importing chals anyway ...'.format(ctfname))
        for chal in chals:
            import_challenge_pad(chal, ctf, ctfpage)

        ALREADY_IMPORTED_CTFS.append(ctfname)


def init_config(args):
    cfg = configparser.ConfigParser()
    if args.config:
        cfg.read(args.config)
    for x in ('wiki', 'ctfpad'):
        if x not in cfg:
            cfg[x] = {}

    for val, section, entry in ((args.wiki_url, 'wiki', 'url'),
                                (args.wiki_user, 'wiki', 'user'),
                                (args.wiki_password, 'wiki', 'password'),
                                (args.ctfpad_apikey, 'ctfpad', 'apikey'),
                                (args.ctfpad_url, 'ctfpad', 'url')):
        if val:
            cfg[section][entry] = val
        elif entry not in cfg[section]:
            log.error("Missing %s/%s (either in config file or command line)",
                      section, entry)
            sys.exit(-1)

    if 'categorymap' in cfg:
        for k, v in cfg['categorymap'].items():
            CTF_CATEGORY_MAP[k] = v

    global OVERWRITE_ALL
    global OVERWRITE_CTFS
    if args.overwrite:
        if len(args.overwrite) == 1 and args.overwrite[0].lower() == 'all':
            OVERWRITE_ALL = True
        else:
            OVERWRITE_CTFS.extend(args.overwrite)

    global UPLOAD_IMAGES_TO_WIKI
    if 'uploadimages' in cfg['wiki']:
        UPLOAD_IMAGES_TO_WIKI = cfg['wiki']['uploadimages']
    if args.wiki_upload_images:
        UPLOAD_IMAGES_TO_WIKI = args.wiki_upload_images

    global MAX_SOURCE_LINES
    if 'uploadimages' in cfg['wiki']:
        UPLOAD_IMAGES_TO_WIKI = cfg['wiki']['maxsrclines']
    if args.wiki_max_src_lines:
        UPLOAD_IMAGES_TO_WIKI = args.wiki_max_src_lines

    return cfg


def init(config):
    log.info("connecting to ctfpad")
    global cl
    cl = CTFPadClient(config['ctfpad']['url'],
                      config['ctfpad']['apikey'],
                      ssl_verify=True)
    log.info("running ctfpad client as user '%s'", cl.whoami()['username'])

    log.info("connecting to mediawiki")
    global site
    url = config['wiki']['url']
    url = urlparse(url)
    log.debug("mediawiki url: %s", url)
    hostname = url.netloc
    path = url.path
    proto = url.scheme
    user = config['wiki']['user']
    password = config['wiki']['password']
    site = mwclient.Site((proto, hostname), path=path)
    site.login(user, password)


def main():
    parser = argparse.ArgumentParser()

    # login related args
    group = parser.add_argument_group('credentials')

    group.add_argument("--wiki-url",
                       help="URL to mediawiki")
    group.add_argument("--wiki-user",
                       help="mediawiki username")
    group.add_argument("--wiki-password",
                       help="mediawiki password")
    group.add_argument("--ctfpad-apikey",
                       help="API key of ctfpad user")
    group.add_argument("--ctfpad-url",
                       help="URL to ctfpad")

    group.add_argument("-c", "--config",
                       help="ini style config file. if not given all other"
                            " credential options must be set.")

    # importing related args
    parser.add_argument("--overwrite", nargs="*", default=None,
                        help='Overwrite the contents of the wiki pages, if'
                             'they exist, of the given list of'
                             ' CTFs or \"all\" for all exported pages.')
    parser.add_argument("--imported-ctf-list",
                        default=None, type=str,
                        help="path to json file containing already "
                             " import ctfs")

    # wiki import options
    parser.add_argument("--wiki-max-src-lines",
                        type=int, default=None,
                        help="maximum number of lines of source code to embed"
                             " in wiki")
    parser.add_argument("--wiki-upload-images",
                        action='store_true',
                        help="whether to upload images to the wiki or embed"
                             " them as external images.")

    # logging related args
    parser.add_argument('--logfile',
                        default="", type=str,
                        help='Log output of this script to this file')
    parser.add_argument('-q', '--quiet',
                        default=False, action='store_true',
                        help='Surpress console log output')
    parser.add_argument("-v", "--verbose",
                        action='store_true',
                        help="enable debug log")

    args = parser.parse_args(sys.argv[1:])

    global log
    log = setup_logging(console=(not args.quiet),
                        logfile=args.logfile,
                        loglevel=("debug" if args.verbose else "info"))

    config = init_config(args)

    init(config)

    if args.imported_ctf_list:
        try:
            load_imported_ctfs_from(args.importedctflist)
        except:
            log.info("importing all ctfs")

    if OVERWRITE_ALL:
        log.info("Overwriting pages set to: {}".format(OVERWRITE_ALL))
    elif OVERWRITE_CTFS:
        log.info("Overwriting pages belogning to CTFs: {}"
                 .format(OVERWRITE_CTFS))
    else:
        log.info("Not overwriting any ctf pages")

    cats = list(set(CTF_CATEGORY_MAP.values()))
    create_ctf_category_pages(cats)

    import_ctf_pads()

    if args.imported_ctf_list:
        try:
            dump_imported_ctfs_to(args.importedctflist)
        except:
            log.warning("couldn't save list of exported ctfs",
                        exc_info=sys.exc_info())
