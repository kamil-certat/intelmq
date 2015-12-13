# -*- coding: utf-8 -*-
"""
"""
from __future__ import unicode_literals

import json
import sys

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event

TYPES = {
    'PHISHING': 'phishing',
    'MALWARE': 'malware',
    'EXPLOIT_KIT': 'exploit',
    'BACKDOOR': 'backdoor'
}


class BluelivCrimeserverParserBot(Bot):

    def process(self):
        report = self.receive_message()
        if report is None or not report.contains('raw'):
            self.acknowledge_message()
            return

        raw_report = utils.base64_decode(report.value('raw'))

        for item in json.loads(raw_report):
            event.add('source.url', item['url'], sanitize=True)
            event.add('source.ip', item['ip'], sanitize=True)
            event.add('source.geolocation.cc', item['country'], sanitize=True)
            event.add('classification.type', TYPES[item['type']], sanitize=True)
            event.add('time.source', item['firstSeenAt'][:-4] + '+00:00',
                      sanitize=True)
            event.add("raw", json.dumps(item, sort_keys=True),
                      sanitize=True)
            self.send_message(event)
        self.acknowledge_message()

if __name__ == "__main__":
    bot = BluelivCrimeserverParserBot(sys.argv[1])
    bot.start()
