import os
import yara
import config
import hashlib
from Detector import Detector

rules_dir = os.path.join(config.PROJECT_FOLDER, "rules")


class YaraScanner(Detector):

    def __init__(self, input_file, read_file=True):
        super(self.__class__, self).__init__(self, input_file, read_file)
        self.rules_file = os.path.join(rules_dir, "master.yara")
        self.rule_compiled = None
        self.file_hash = hashlib.sha256(self.file_data).hexdigest()

    def detect(self):
        result = dict()
        matched_rules = list()

        scan_results = self.rule_compiled.match(self.file_path)
        for res in scan_results:
            print "Hit = {}".format(str(res.rule))


    def can_process(self):
        if not os.path.isfile(self.file_path):
            return False

        with open(self.rules_file) as rf:
            self.rule_compiled = yara.compile(file=rf)

        if not self.rule_compiled:
            return False