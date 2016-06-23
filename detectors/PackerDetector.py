import os
import pefile
import peutils
import config
from Detector import Detector

cur_dir = os.path.dirname(os.path.abspath(__file__))
signatures_file = os.path.join(config.FILES_FOLDER, "userDB.txt")


class PackerDetector(Detector):
    def __init__(self, input, process_input=True):
        super(self.__class__, self).__init__(input, process_input)
        self.sig = peutils.SignatureDatabase(signatures_file)
        self.pe_file = None

    def detect(self):

        result = dict()
        pe = pefile.PE(self.file_data, fast_load=True)
        matches = self.sig.match(pe, ep_only=True)

        if not matches:
            return result

        if len(matches) > 0:
            result['result'] = list(str(matches[0]))
            result['folder'] = 'packed'

    def can_process(self):

        try:
            self.pe_file = pefile.PE(self.file_path, fast_load=True)
        except:
            return False

        return True
