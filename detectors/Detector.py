import os
import inspect
import datetime


class Detector(object):

    def __init__(self, input_file, read_file=False):

        # self.name = self.__class__.__name__.lower()
        # self.location = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
        self.file_path = input_file
        if read_file:
            with open(input_file, "rb") as f:
                self.file_data = f.read()

    def detect(self):
        pass