import urllib.request
import json
import datetime
import csv

# standard time:2018-12-31 23:58:24
standardTimestamp = 1546300704
standardHeight = 1738922

# delta
delta = 600


def get_timestamp(height):
    response = urllib.request.urlopen("https://moneroblocks.info/api/get_block_header/" + str(height))
    b = response.read()
    res = json.loads(str(b.decode()))
    timestamp = res['block_header']['timestamp']
    # print("height: " + str(height) + "\ttime: " + str(datetime.datetime.utcfromtimestamp(timestamp)) + "(" + str(timestamp) + ")")
    return timestamp


def get_delta_height(time, sttime):
    if time == sttime:
        return 0
    if time > sttime:
        return int((time - sttime) / 120) + 1
    else:
        return int((time - sttime) / 120) - 1


def get_left_near_height(timestamp):
    h = standardHeight + get_delta_height(timestamp, standardTimestamp)
    time = get_timestamp(h)
    while True:
        if time <= timestamp and time > timestamp - delta:
            break
        h = h + get_delta_height(timestamp, time)
        time = get_timestamp(h)
    return h


def get_right_near_height(timestamp):
    h = standardHeight + get_delta_height(timestamp, standardTimestamp)
    time = get_timestamp(h)
    while True:
        if time >= timestamp and time < timestamp + delta:
            break
        h = h + get_delta_height(timestamp, time)
        time = get_timestamp(h)
    return h


def get_block_info(height):
    response = urllib.request.urlopen("https://moneroblocks.info/api/get_block_header/" + str(height))
    b = response.read()
    res = json.loads(str(b.decode()))
    return res['block_header']['timestamp'], res['block_header']['hash']


def get_block_creation_time(stime, etime, out_path):
    left_height = get_left_near_height(stime)
    right_height = get_right_near_height(etime)

    with open(out_path, 'w', newline='') as fout:
        writer = csv.writer(fout)
        for h in range(left_height, right_height + 1):
            res = get_block_info(h)
            line = [res[0], res[1]]
            writer.writerow(line)




