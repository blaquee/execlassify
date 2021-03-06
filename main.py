import os
import sys
import pefile
import peutils
import argparse
import time
from shutil import copyfile, copy, copy2

import config

cur_dir = os.path.dirname(os.path.abspath(__file__))
signatures_file = os.path.join(config.FILES_FOLDER, "userDB.txt")
sig = peutils.SignatureDatabase(signatures_file)


def load_detectors(folder):

    detectors = {}
    for file_name in os.listdir(folder):

        if not file_name.endswith(".py"):
            continue

        if file_name == "Detector.py":
            continue

        module_name = os.path.splitext(file_name)[0]
        module = __import__(module_name)

        detection_name = module_name
        # print "Detector name: {}".format(detection_name)
        detection = getattr(module, detection_name)

        # print "Detection_name: {}\tdetection: {}".format(detection_name, detection.__name__)
        detectors[detection_name] = detection

    return detectors


def make_directory(dir):
    if not os.path.exists(dir):
        os.makedirs(dir)


def abs_file_paths(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


def main():
    # log_file = os.path.join(config.LOGS_FOLDER, "stdout.log")
    # sys.stdout = open(log_file, "a")

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", help="Directory containing PE Files", default=None, required=True)
    parser.add_argument("-u", "--unpack", help="Automatically unpack UPX packed files", action="store_false")
    parser.add_argument("-t", "--tenant", help="Tenant for current samples corupus", required=False)
    parser.add_argument("-i", "--input", help="Input string, can be a file, url for plugin processing", required=False)

    args = parser.parse_args()

    threat_info = dict()
    file_list = list()
    detector_plugins = list()

    # Set up Results folder
    results_path = config.RESULTS_FOLDER
    make_directory(results_path)

    # load detector plugins
    detector_plugins = load_detectors(config.PLUGINS_FOLDER)
    print "Detector Plugins available:\n{}".format(detector_plugins)

    if args.tenant:
        processing_path = os.path.join(results_path, args.tenant)
        make_directory(processing_path)
    else:
        processing_path = os.path.join(results_path, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()))
        make_directory(processing_path)

    # create sub path for detectors
    detector_results = os.path.join(processing_path, "detectors")
    make_directory(detector_results)

    '''
    packed_path = os.path.join(processing_path, "packed")
    make_directory(packed_path)

    installer_path = os.path.join(processing_path, "installers")
    make_directory(installer_path)
    '''

    # directory sanity check
    if os.path.isdir(args.dir):
        for files in abs_file_paths(args.dir):
            threat_info[files] = list()

            for name in detector_plugins:
                # Call the detectors constructor
                detector = detector_plugins[name](files)

                if not detector.can_process():
                    # this detector doesnt want this input, skip it
                    continue

                result = detector.detect()
                if not result:
                    # there were no results for this input
                    continue

                threat_info[files].append(result)
        '''
        # overlay, possible setup file
        for f in file_list:
            if is_overlay(f):
                threat_info[files].append({"result":"overlay"})
                try:
                    copy2(f, installer_path)
                except:
                    pass
            res, match = is_packed(f)
        # if file packed, place in packed dictionary
            if res:
                threat_info[files].append(match)
                packed_files[files] = match
        '''

    for k, v in threat_info.iteritems():
        for entries in v:
            for key, value in entries.iteritems():
                print "File:{}\n\tDetector:{}\nResult:{}\n\n".format(k, key, str(value))


if __name__ == '__main__':
    main()
