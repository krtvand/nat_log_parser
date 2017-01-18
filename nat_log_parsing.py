"""
Скрипт позволяет найти те IP адреса, сессии которых
одновременно присутствовали во всех представленных лог файлах
"""

__author__ = "Andrey Kartaev"

NAT_LOG_FILES = ['vk-02-09-1335', 'vk-02-09-1340', 'vk-02-09-1105', 'vk-01-09-2115', 'vk-01-09-1920']

from collections import namedtuple

# Log line representation in named tuple
NATLogFileLine = namedtuple('NATLogLine',
                            'date, time, action, '
                            'protocol, sourcelocal, '
                            'arrow, destlocal, '
                            'sourceglobal, arrow2, destglobal')


def line_to_tuple(line):
    _tuple = tuple(line.split())
    return NATLogFileLine._make(_tuple)


def tuples_from_file(file):
    for line in open(file, 'r'):
        yield line_to_tuple(line)
        # tup = map(line_to_tuple, open(file, 'r').readlines())


def uniqe_ip_from_file(file):
    """Getting uniqe ip source local addresses from all sessions in file

    :param file: (String) file name to read
    :return: set of uniqe ip source local addresses
    """
    uniqe_ip = set()
    for t in tuples_from_file(file):
        # from ip:port get only ip
        sourcelocal = t.sourcelocal.split(':')[0]
        if sourcelocal not in uniqe_ip:
            uniqe_ip.add(sourcelocal)
    return uniqe_ip


def log_file_intersection(log_files):
    """Get intersection of sessions, that presented in all log files

    intersection is based on source local ip address
    :param log_files: list of log file names
    :return: set of uniqe ip addresses
    """
    intersec = set()
    for file in log_files:
        if not intersec:
            intersec = uniqe_ip_from_file(file)
        else:
            intersec = intersec.intersection(uniqe_ip_from_file(file))
    return intersec


if __name__ == "__main__":
    print(len(log_file_intersection(NAT_LOG_FILES)))
    print(log_file_intersection(NAT_LOG_FILES))
