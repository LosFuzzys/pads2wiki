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


import logging
try:
    import colorlog
except:
    colorlog = None

def setup_logging(console=True, logfile=None,
                  loglevel=logging.INFO,
                  name="pads2wiki"):
    log = logging.getLogger(name)
    log.handlers = []
    if loglevel == 'debug':
        log.setLevel(logging.DEBUG)
    elif loglevel == 'info':
        log.setLevel(logging.INFO)
    else:
        log.setLevel(loglevel)
    if console and colorlog:
        handler = colorlog.StreamHandler()
        fmt = '%(log_color)s%(levelname)-8s%(reset)s : %(name)s :: %(message)s'
        fmter = colorlog.ColoredFormatter(fmt)
        handler.setFormatter(fmter)
        log.addHandler(handler)
    elif console and not colorlog:
        fmt = '%(levelname)-8s : %(name)s :: %(message)s'
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt))
        log.addHandler(handler)

    if logfile:
        log.debug("logging to file '{}'".format(logfile))
        handler = logging.FileHandler(logfile)
        fmt = '%(asctime)s ; %(levelname)s ; %(name)s ; %(message)s'
        handler.setFormatter(logging.Formatter(fmt, "%Y-%m-%d %H:%M"))
        log.addHandler(handler)

    return log
