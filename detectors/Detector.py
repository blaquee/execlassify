import os
import inspect
import datetime


class Detector(object):

    def __init__(self, input, process_input=False):

        # self.name = self.__class__.__name__.lower()
        # self.location = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
        self.file_path = input
        if process_input:
            with open(input, "rb") as f:
                self.file_data = f.read()

    def detect(self):
        pass

    def can_process(self):
        return False