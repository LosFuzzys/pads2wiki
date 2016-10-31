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


import requests


class CTFPadClientRequestFailed(Exception):
    pass


class CTFPadClient:

    @staticmethod
    def from_files(remotef, apikeyf, **kwargs):
        with open(apikeyf) as f:
            apikey = f.read().strip()
        with open(remotef) as f:
            remote = f.read().strip()
        return CTFPadClient(remote, apikey, **kwargs)

    def __init__(self, remote, apikey, ssl_verify=True):
        if not remote.endswith("/"):
            remote = remote + "/"
        self.remote = remote
        self.apikey = apikey
        self._sess = requests.session()
        self._headers = {"X-Apikey": apikey}
        self.ssl_verify = ssl_verify

    def get(self, path, **kwargs):
        resp = self._sess.get(self.remote + path,
                              headers=self._headers,
                              verify=self.ssl_verify)
        if resp.ok:
            return resp.json()
        else:
            raise CTFPadClientRequestFailed("{} - {}".format(resp.url,
                                                             resp.status_code))

    def get_raw(self, path, binary=False):
        resp = self._sess.get(self.remote + path,
                              headers=self._headers,
                              verify=self.ssl_verify)
        if resp.ok:
            if binary:
                return resp.content
            else:
                return resp.text
        else:
            raise CTFPadClientRequestFailed("{} - {}".format(resp.url,
                                                             resp.status_code))

    def whoami(self):
        return self.get("user/whoami")

    def ctfs(self):
        return self.get("ctfs")

    def ctf(self, ctfid):
        return self.get("ctfs/{}".format(int(ctfid)))

    def ctf_pad_html(self, ctfid):
        return self.get("ctfs/{}/html".format(int(ctfid)))

    def ctf_pad_text(self, ctfid):
        return self.get("ctfs/{}/text".format(int(ctfid)))

    def challenges(self, ctfid):
        return self.get("ctfs/{}/challenges".format(int(ctfid)))

    def challenge(self, chalid):
        return self.get("challenges/{}".format(int(chalid)))

    def challenge_pad_html(self, chalid):
        return self.get("challenges/{}/html".format(int(chalid)))

    def challenge_pad_text(self, chalid):
        return self.get("challenges/{}/text".format(int(chalid)))

    def challenge_files(self, chalid):
        return self.get("challenges/{}/files".format(int(chalid)))

    def file_content(self, file):
        if "name" not in file or "id" not in file:
            raise ValueError("file param is not a valid file description")
        if 'path' in file:
            p = file['path']
        else:
            p = "file/{}/{}".format(file['id'], file['name'])
        return bytes(self.get_raw(p.lstrip("/"), binary=True))


if __name__ == "__main__":
    from pprint import pprint
    cl = CTFPadClient.from_files("./remote.txt", "./apikey.txt",
                                 ssl_verify=False)
    pprint(cl.whoami())
    ctfs = cl.ctfs()
    pprint(ctfs)
    ctf = ctfs['ctfs'][0]
    pprint(ctf)
    ctfid = ctf['id']
    ctfdata = cl.ctf(ctfid)
    pprint(ctfdata)
    ctfpad = cl.ctf_pad_html(ctfid)
    pprint(ctfpad)
    chals = cl.challenges(ctfid)
    pprint(chals)
    chal = chals['challenges'][1]
    pprint(chal)
    chalid = chal['id']
    chal = cl.challenge(chalid)
    pprint(chal)
    chalpad = cl.challenge_pad_html(chalid)
    pprint(chalpad)
    chalpad = cl.challenge_pad_text(chalid)
    pprint(chalpad)
    files = cl.challenge_files(chalid)
    pprint(files)

    ctfpadh = cl.ctf_pad_html(3)['html']
    ctfpadt = cl.ctf_pad_text(3)['text']
    print("-" * 30)
    print(ctfpadh)
    print("-" * 30)
    print(ctfpadt)
    print("-" * 30)
    # with open("./pad-test.md", "w") as f:
    #     f.write(ctfpadt.encode('utf-8'))

    # ctfpadh = cl.challenge_pad_html(35)['html']
    # ctfpadt = cl.challenge_pad_text(35)['text']
    # print("-" * 30)
    # print(ctfpadh)
    # print("-" * 30)
    # print(ctfpadt)
    # print("-" * 30)
    # with open("./pad-test-2.md", "w") as f:
    #     f.write(ctfpadt.encode('utf-8'))
