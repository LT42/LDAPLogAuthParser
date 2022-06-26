import argparse
import re
from datetime import datetime, timedelta

##################################################################################
#
# Script to parse failed logins against the LDAP server from an openLDAP log file
# Author: Lukas Thiel
# License: GPLv3
# Version: 1.0
# Last modified: Jun 2022
# Modified by: Lukas Thiel
#
# This script parses a given logfile and filters err=49 lines out
# afterwards it matches the connection and operation ids from this lines and
# looks for the failed usernames, lists these in a list and prints it as a table
# or in a json string
#
# Usage: main.py
# prints help
#
##################################################################################

# The script assumes that the logfile is given in OpenLDAP standard format, which delivers the following columns
# columns=['month', 'day', 'time', 'server', 'process', 'conn', 'op', 'payload']

debug = False

# function to parse lines with err=49
def check_log_lines_with_errors(filename, days):
    # initialize working variables
    err_row_list = list()
    fire = False

    month_array = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    # open log file to parse all error lines into a smaller list
    with open(filename, 'r') as f:
        if debug:
            print('Parsing log file and search for errors')

        lines = f.readlines()
        # for progress percent view
        ten_hit = 0

        for index, line in enumerate(lines):
            # print progress in percent
            if debug:
                if (int((index * 100) / len(lines)) % 10 == 0) & (int((index * 100) / len(lines)) != ten_hit):
                    ten_hit = int((index * 100) / len(lines))
                    print(str(int((index * 100) / len(lines))) + "%...", end='')

            # split columns
            columns = re.split('\\s+', line, maxsplit=7)

            # working variables for time slot
            month = str(columns[0])
            day = int(columns[1])

            # begin search when first day is hit
            if not fire and month_array[int(days.month) - 1] == month and int(days.day) == day:
                fire = True

            # append all lines with err=49 to err_row_list
            if fire:
                if 'err=49' in str(columns[7]):
                    err_row_list.append(columns)

    # return err_row_list
    return err_row_list

# function to parse usernames from err connections and operations
def parse_username_from_log(filename, err_row_list, uid_search_str):
    user_error_dict = dict()

    # open log file (again)
    with open(filename, 'r') as f:

        # for progress percent view
        ten_hit = 0

        lines = f.readlines()

        if debug:
            print('Parsing log file for usernames')
        for index, line in enumerate(lines):
            # print progress
            if debug:
                if (int((index * 100) / len(lines)) % 10 == 0) & (int((index * 100) / len(lines)) != ten_hit):
                    print(str(int((index * 100) / len(lines))) + "%...", end='')
                    ten_hit = int((index * 100) / len(lines))

            # split columns
            columns = re.split('\\s+', line, maxsplit=7)

            # only match if username is found if set (see main)
            if uid_search_str in columns[7]:
                # iterate over err_row_list
                for error_row in err_row_list:
                    # match conn
                    if columns[5].strip() == error_row[5].strip():
                        # match op
                        if columns[6].strip() == error_row[6].strip():
                            # match uid
                            matches = re.search('uid=([^,]+),', columns[7])

                            if matches:
                                # parse username via RegEx
                                username = matches.group(1)

                                # if username is in dict, iterate counter
                                if username in user_error_dict:
                                    user_error_dict[username] = user_error_dict[username] + 1
                                # else put username into dict
                                else:
                                    user_error_dict[username] = 1
    # return the usernames
    return user_error_dict


if __name__ == '__main__':
    # parse cli parameters
    parser = argparse.ArgumentParser(description="LDAP Log AuthParser")
    parser.add_argument('-f', '--logfile', type=str, required=True, dest='logfilepath', help='logfile path')
    parser.add_argument('-d', '--days', type=int, dest='days', help='how many days should be parsed (default: 7)', default=7, metavar="days")
    parser.add_argument('-u', '--uid', type=str, dest='uid', help='uid')
    parser.add_argument('-j', '--json', help='if set result will be printed in json format', action='store_true')
    parser.add_argument('-v', '--verbose', help='print what you are doing', action='store_true')
    args = parser.parse_args()

    # debug mode
    if args.verbose:
        debug = True

    # logfile path
    logfile_path = args.logfilepath

    # username to filter may be set
    uid_search = 'uid='
    if args.uid:
        uid_search += str(args.uid).replace("'", "").strip()

    # calculate days
    search_today_time = datetime.today()
    search_back_time = datetime.today() - timedelta(days=args.days)

    # parse error lines from logfile
    err_rows = check_log_lines_with_errors(logfile_path, search_back_time)

    if debug:
        print('\nGoing on')

    # parse usernames from logfile
    usernames_with_error_dict = parse_username_from_log(logfile_path, err_rows, uid_search)

    if debug:
        if not usernames_with_error_dict:
            print('No failed logins found in the last', args.days, 'days')
        else:
            print('Found the following failed logins in the last', args.days, 'days')

    # sort array
    sorted_user_errors = dict(sorted(usernames_with_error_dict.items(), key=lambda item: item[1], reverse=True))

    # switch json or table output
    if args.json:
        print('[', end='')
        print(sorted_user_errors)
        print(']', end='')
    else:
        print('Username', '\t', 'Failed login counter')

        for key in sorted_user_errors.keys():
            print(key, '\t', sorted_user_errors[key])