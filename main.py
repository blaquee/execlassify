import os
import sys
import pefile
import peutils
import argparse

import config

cur_dir = os.path.dirname(os.path.abspath(__file__))
signatures_file = os.path.join(config.FILES_FOLDER, "userDB.txt")
sig = peutils.SignatureDatabase(signatures_file)


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


def process_overlay(pe):
    pass


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
    if not os.path.exists(results_path):
        os.makedirs(results_path)

    if args.tenant:
        tenant_path = os.path.join(results_path, args.tenant)
        if not os.path.exists(tenant_path):
            os.makedirs(tenant_path)

    if args.dir:
        if os.path.isdir(args.dir):
            for files in abs_file_paths(args.dir):

                try:
                    pe = pefile.PE(files, fast_load=True)
                except:
                    print "Error loading {}..is it a PE?".format(files)
                    continue

                print "File {}".format(files)
                res,match = is_packed(pe)
                if res:
                    packed_files[files] = match

    for k,v in packed_files.iteritems():
        print "{} -> {}".format(k, v)


if __name__ == '__main__':
    main()
