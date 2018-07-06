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

import os
from setuptools import setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


setup(name="pads2wiki",
      description="Import pad contents managed by CTFPad into a mediawiki.",
      long_description=read("README.md"),
      url="https://github.com/LosFuzzys/pads2wiki",
      version="0.0.1",
      license='Apache 2.0',
      install_requires=[
          "mwclient",
          "pypandoc",
          "requests",
          ],
      entry_points = {
          'console_scripts': [
              'pads2wiki = pads2wiki:main',
              ],
          },
      packages=['pads2wiki'],
      classifiers = [
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: Science/Research',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache License',
          'Natural Language :: English',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 3.5',
          ]
)
