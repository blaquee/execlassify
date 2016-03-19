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


def make_directory(dir):
    if not os.path.exists(dir):
        os.makedirs(dir)


def abs_file_paths(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


def un_upx(packed_file):
    pass


def is_packed(pe_file):
    global sig

    matches = sig.match(pe_file, ep_only=True)

    if not matches:
        return False, ""
    else:
        if len(matches) > 0:
            return True, str(matches[0])


# currently only checks for overlay. NullSoft also seems to always
# have a section named .ndata with a VirtualSize of 0x00008000, but have to
# get a larger sample set to be sure
def is_overlay(pe_file):
    if not pe_file.get_overlay_data_start_offset():
        return False

    return True


def main():
    # log_file = os.path.join(config.LOGS_FOLDER, "stdout.log")
    # sys.stdout = open(log_file, "a")

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", help="Directory containing PE Files", default=None, required=True)
    parser.add_argument("-u", "--unpack", help="Automatically unpack UPX packed files", action="store_false")
    parser.add_argument("-t", "--tenant", help="Tenant for current samples corupus", required=False)

    args = parser.parse_args()
    packed_files = dict()

    # Set up Results folder
    results_path = config.RESULTS_FOLDER
    make_directory(results_path)

    if args.tenant:
        processing_path = os.path.join(results_path, args.tenant)
        make_directory(processing_path)
    else:
        processing_path = os.path.join(results_path, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()))
        make_directory(processing_path)

    packed_path = os.path.join(processing_path, "packed")
    make_directory(packed_path)

    installer_path = os.path.join(processing_path, "installers")
    make_directory(installer_path)

    # directory sanity check
    if os.path.isdir(args.dir):
        for files in abs_file_paths(args.dir):
            try:
                pe = pefile.PE(files, fast_load=True)
            except:
                print "Error loading {}..is it a PE?".format(files)
                continue
            print "File {}".format(files)
            res, match = is_packed(pe)

            # overlay, possible setup file
            if is_overlay(pe):
                try:
                    copy2(pe, installer_path)
                except:
                    pass
            # if file packed, place in packed folder
            if res:
                packed_files[files] = match

    for k, v in packed_files.iteritems():
        # copy files to packed folder
        try:
            copy2(k, packed_path)
        except:
            pass
        print "{} -> {}".format(k, v)


if __name__ == '__main__':
    main()
