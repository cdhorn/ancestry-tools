#!/usr/bin/env python3
"""
##############################################################################
# Copyright 2018-2020 Christopher Horn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##############################################################################
"""
import argparse
import logging
import os
import re
import sys
import time
from io import StringIO
from multiprocessing import Lock, Process, Queue

import toml
import pendulum


def clean_date(date):
    """
    Perform date format cleanup
    """
    months = [
        "JAN",
        "FEB",
        "MAR",
        "APR",
        "MAY",
        "JUN",
        "JUL",
        "AUG",
        "SEP",
        "OCT",
        "NOV",
        "DEC",
    ]
    index = 0
    prefix = date[:7]
    result = ""
    data = date[7:].upper().strip()
    letter = word = False
    while index < len(data):
        if data[index] == "0" and not word:
            index = index + 1
            continue
        if data[index] == " ":
            word = False
        else:
            word = True
            if data[index].isalpha:
                letter = True
            elif data[index].isdigit and letter:
                result = result + " "
                word = False
        result = result + data[index]
        index = index + 1

    for month in months:
        if month in result:
            match = re.search(r"" + month + "\w+", result)
            if not match:
                logging.info(
                    "MONTH: {} RESULT: {} BUT MATCH NONE?".format(month, result)
                )
            else:
                result = result.replace(str(match.group()), month)

    result = result.replace("ABOUT", "ABT")
    result = result.replace("BEFORE", "BEF")
    result = result.replace("AFTER", "AFT")
    result = result.replace("BETWEEN", "BET")
    result = result.replace("FROM", "")
    result = result.replace("TO", "AND")

    if "AND" in result and "BET" not in result:
        result = "BET {0}".format(result)

    if "-" in result:
        split = result.split("-")
        if result[:1] == "-":
            result = "BEF {0}".format(split[1])
        elif result[-1:] == "-":
            result = "AFT {0}".format(split[0])
        elif len(split) == 2:
            result = "BET {0} AND {1}".format(split[0], split[1])

    while "  " in result:
        result = result.replace("  ", " ")

    return "{0}{1}\n".format(prefix, result)


def clean_place(place, places):
    """
    Perform place name cleanup and optional substitution for bulk edits
    """
    result = place
    result = result.replace("  ", " ")
    for match in places:
        result = result.replace(match, places[match])
    return result


def build_note(text, level=1, limit=180, strip=True, keyword="NOTE"):
    """
    Format a note for gedcom output
    """
    note = []
    key = int(level)
    tag = keyword
    data = text
    if strip:
        data = data.strip()
    while data != "":
        index = limit
        if len(data) < limit:
            index = len(data)
        else:
            while data[index - 1] == " " and index > 0:
                index = index - 1
        chunk = data[:index]
        data = data[index:]
        entry = "{0} {1} {2}".format(key, tag, chunk)
        note.append(entry)
        tag = "CONC"
        key = int(level) + 1
    return note


def get_dbid_objects(queue, media_base):
    """
    Read in database information for later reference
    """
    dbid_map = {}
    logging.info("Collecting DBID object information")
    for file_object in os.scandir(media_base + "/metadata/dbid"):
        if not file_object.is_file():
            continue
        with open(file_object.path, "r") as toml_file:
            metadata = toml.load(toml_file)
        dbid_map.update({metadata["dbid"]: metadata})
    logging.info("DBID object collection completed")
    queue.put(dbid_map)


def get_guid_objects(queue, media_base, absolute=False):
    """
    Read in GUID object information for later reference
    """
    index = 1
    guid_map = {}
    object_map = {}
    if absolute:
        image_base = "{0}".format(media_base) + "/media/{0}/{1}"
    else:
        image_base = "./media/{0}/{1}"
    logging.info("Collecting GUID object information")
    for file_object in os.scandir(media_base + "/metadata/guid"):
        if not file_object.is_file():
            continue
        with open(file_object.path, "r") as toml_file:
            metadata = toml.load(toml_file)
        base_name = os.path.basename(metadata["image"])
        image_name = image_base.format(metadata["type"], base_name)
        image_extension = image_name.split(".").pop(-1)

        picture_name = metadata["title"]
        if picture_name == "":
            picture_name = "Untitled"

        object_id = "@M{0}@".format(index)
        object_entry = [
            "0 {0} OBJE".format(object_id),
            "1 FILE {0}".format(image_name),
            "1 FORM {0}".format(image_extension),
            "1 TITL {0}".format(picture_name),
        ]

        if metadata["type"] == "portrait":
            object_entry.append("1 TYPE Photo")
        else:
            object_entry.append("1 TYPE {0}".format(metadata["type"].title()))

        if "url" in metadata and metadata["url"] != "":
            object_entry.append("1 NOTE {0}".format(metadata["url"]))

        if "facts" in metadata:
            facts = metadata["facts"]
            for key in ["description", "transcription"]:
                if key in facts and facts[key] != "":
                    note = build_note(facts[key], 1)
                    if len(note) > 0:
                        for item in note:
                            object_entry.append(item)

        object_map.update({object_id: object_entry})
        guid_map.update({metadata["guid"]: object_id})
        index = index + 1
        if index > 99999:
            logging.error("100000 GUID objects not supported, APID range starts there")
            sys.exit(1)
    logging.info("GUID object collection completed")
    queue.put((guid_map, object_map))


def read_apids(local_queue, local_lock, remote_queue, remote_lock):
    """
    Read in requested APID files and push on queue until told to exit
    """
    while True:
        local_lock.acquire()
        if not local_queue.empty():
            file_data = local_queue.get()
            local_lock.release()
        else:
            local_lock.release()
            time.sleep(0.01)
            continue
        if "exit" in file_data and file_data["exit"]:
            break
        with open(file_data["fileName"], "r") as toml_file:
            toml_data = toml.load(toml_file)
        remote_lock.acquire()
        remote_queue.put(toml_data)
        remote_lock.release()


def get_apid_objects(queue, media_base, args, absolute=False):
    """
    Read in all the APID objects for reference using asynchronous workers
    """
    work_lock = Lock()
    work_queue = Queue()

    readers = os.cpu_count()
    read_lock = Lock()
    read_queue = Queue()
    read_processes = []
    for number in range(readers):
        read_process = Process(
            target=read_apids, args=(read_queue, read_lock, work_queue, work_lock)
        )
        read_process.start()
        read_processes.append(read_process)

    logging.info("Collecting APID object information")
    file_list = []
    file_total = 0
    for file_object in os.scandir(media_base + "/metadata/apid"):
        if not file_object.is_file():
            continue
        file_list.append({"fileName": file_object.path})
        file_total = file_total + 1

    read_lock.acquire()
    for item in file_list:
        read_queue.put(item)
    for item in read_processes:
        read_queue.put({"exit": True})
    read_lock.release()

    index = 100000
    apid_image_map = {}
    apid_screenshot_map = {}
    apid_full_map = {}
    object_map = {}
    image_cache = {}
    item_count = 0
    if absolute:
        image_base = "{0}".format(media_base) + "/media/{0}"
    else:
        image_base = "./media/{0}"
    while True:
        work_lock.acquire()
        if not work_queue.empty():
            metadata = work_queue.get()
            work_lock.release()
        else:
            work_lock.release()
            time.sleep(0.01)
            continue

        item_count = item_count + 1
        apid_full_map.update({metadata["apid"]: metadata})
        if "image" in metadata:
            if metadata["image"] not in image_cache:
                base_name = metadata["image"].split("/media/").pop(1)
                image_name = image_base.format(base_name)
                image_extension = image_name.split(".").pop(-1)

                object_id = "@M{0}@".format(index)
                object_entry = [
                    "0 {0} OBJE".format(object_id),
                    "1 FILE {0}".format(image_name),
                    "1 FORM {0}".format(image_extension),
                    "1 TYPE document",
                ]

                object_map.update({object_id: object_entry})
                image_cache.update({metadata["image"]: object_id})
                index = index + 1
            else:
                object_id = image_cache[metadata["image"]]
            apid_image_map.update({metadata["apid"]: object_id})
        if "screenshot" in metadata:
            base_name = os.path.basename(metadata["screenshot"])
            image_name = image_base.format("apid") + "/" + base_name
            image_extension = image_name.split(".").pop(-1)

            if "title" in metadata and metadata["title"] != "":
                title = metadata["title"]
            else:
                title = "Ancestry.com Source Record, {0}".format(metadata["apid"])

            object_id = "@M{0}@".format(index)
            object_entry = [
                "0 {0} OBJE".format(object_id),
                "1 FILE {0}".format(image_name),
                "1 FORM {0}".format(image_extension),
                "1 TITL {0}".format(title),
                "1 REFN {0}".format(metadata["apid"]),
            ]

            if "url" in metadata and metadata["url"] != "":
                object_entry.append("1 NOTE {0}".format(metadata["url"]))

            object_map.update({object_id: object_entry})
            index = index + 1
            apid_screenshot_map.update({metadata["apid"]: object_id})

            if item_count == file_total:
                break

    for read_process in read_processes:
        read_process.join()
    queue.put((apid_image_map, apid_screenshot_map, apid_full_map, object_map))
    logging.info("APID object collection completed")


def get_people_urls(gedcom_data, apid_full_map):
    """
    Read in all the person URLs for later reference
    """
    people = {}
    found = False
    logging.info("Extracting person specific URL information")
    for line in gedcom_data.split("\n"):
        if len(line) > 5:
            tag = line.split(" ")[1]
            if "@P" in tag:
                person = tag
                found = False
                continue
            if tag == "_APID" and not found:
                apid = line.split(" ")[2]
                if apid in apid_full_map:
                    if "person_url" in apid_full_map[apid]:
                        if apid_full_map[apid]["person_url"] != "":
                            people.update({person: apid_full_map[apid]["person_url"]})
                            found = True
    logging.info("Person URL extraction completed")
    return people


def get_sources(queue, args, gedcom_data, dbid_map, apid_image_map):
    """
    Read in and build cleaned up source records for later reference
    """
    sources = {}
    dbid_list = []
    source_list = []
    logging.info("Generating updated source records")
    gedcom = StringIO(gedcom_data)
    line = gedcom.readline()
    while line:
        if "0 @S" not in line:
            if " _APID " in line:
                dbid = line.split(",")[1].split(":")[0]
                if dbid not in dbid_list:
                    dbid_list.append(dbid)
            if " SOUR " in line:
                source = line.split(" ")[2].strip()
                if source not in source_list:
                    source_list.append(source)
            line = gedcom.readline()
            continue
        apid = ""
        source = []
        source_data = [line]
        source_id = line.split(" ")[1]
        if source_id not in source_list:
            logging.error("Found unreferenced source record %s", source_id)
            line = gedcom.readline()
            continue
        line = gedcom.readline().strip()
        while line[0] != "0":
            source_data.append(line)
            if "_APID" in line:
                apid = line.strip().split(" ")[2]
                dbid = apid.split(":").pop(0).split(",").pop(1)
                if dbid not in dbid_list:
                    logging.error(
                        "Found unreferenced DBID record %s in source record %s",
                        dbid,
                        source_id,
                    )
                    line = gedcom.readline()
                    continue
            line = gedcom.readline().strip()
        if apid == "":
            sources.update({source_id: source_data})
            continue
        original = []
        publisher = []
        description = []
        if dbid in dbid_map:
            if "publisher" in dbid_map[dbid] and dbid_map[dbid]["publisher"] != "":
                publisher = build_note(dbid_map[dbid]["publisher"], keyword="PUBL")
            if "original" in dbid_map[dbid] and dbid_map[dbid]["original"] != "":
                original = build_note(
                    "Original Data: {0}".format(dbid_map[dbid]["original"]),
                    keyword="NOTE",
                )
            if "description" in dbid_map[dbid]:
                if dbid_map[dbid]["description"] not in ["", "Learn more..."]:
                    description = build_note(
                        dbid_map[dbid]["description"], keyword="NOTE"
                    )
        else:
            logging.error("Found DBID record %s with no data", dbid)
        in_title = False
        in_publisher = False
        short_title = apid = ""
        for entry in source_data:
            if " _APID " in entry:
                apid = entry
                continue
            if in_title:
                if " CONC " in entry or " CONT " in entry:
                    source.append(entry)
                    continue
                in_title = False
                if short_title != "":
                    source.append("1 ABBR {0}".format(short_title))
            if in_publisher:
                if " CONC " in entry or " CONT " in entry:
                    source.append(entry)
                    continue
                in_publisher = False
                if args.source_url:
                    source.append(
                        "1 NOTE https://search.ancestry.com/search/db.aspx?dbid={0}".format(
                            dbid
                        )
                    )
            if "NOTE" in entry and len(entry) < 8:
                continue
            if "CONC" in entry and len(entry) < 8:
                continue
            if " PUBL " in entry:
                if publisher != []:
                    for item in publisher:
                        source.append(item)
                else:
                    source.append(entry)
                in_publisher = True
                continue
            if " TITL " in entry:
                if len(entry[7:].strip()) <= 60:
                    short_title = entry[7:].strip()
                in_title = True
            source.append(entry)
        if original != []:
            for item in original:
                source.append(item)
        if description != []:
            for item in description:
                source.append(item)
        search = apid.split(":").pop(0) + "::"
        for entry in apid_image_map:
            if search in entry:
                source.append("1 OBJE {0}".format(apid_image_map[entry]))
        if args.keep_apid:
            source.append("1 _APID {0}".format(apid))
        sources.update({source_id: source})
    logging.info("Updated source records generated")
    queue.put(sources)


def emit_line(handle, data):
    """
    Write out a line of Gedcom data insuring it does not exceed allowed length
    """
    if len(data) > 254:
        if " PAGE " in data:
            data = data.replace("Record Group Title", "Record Group")
            data = data.replace("Series Title", "Series")
            data = data.replace(
                "Washington, D.C.; Washington, D.C.;", "Washington, D.C.;"
            )
        if len(data) > 254:
            logging.error("Truncating invalid line length: %s", data)
            data = "{0}\n".format(data[:254])
    handle.write(data)


def main():
    """
    Main program logic
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--absolute",
        action="store_true",
        default=False,
        help="Generate absolute file path references",
    )
    parser.add_argument("-b", "--base_dir", help="Base directory")
    parser.add_argument(
        "-B",
        "--build-citation-page",
        action="store_true",
        dest="citation_page",
        default=False,
        help="If missing attempt to build citation page from extracted facts",
    )
    parser.add_argument("-c", "--config", help="Configuration file")
    parser.add_argument(
        "-C",
        "--citation-url",
        action="store_true",
        dest="citation_url",
        default=False,
        help="Include Ancestry.com source citation URL",
    )
    parser.add_argument(
        "-d",
        "--clean-dates",
        action="store_true",
        dest="clean_dates",
        default=False,
        help="Perform simple date cleanups",
    )
    parser.add_argument(
        "-D",
        "--source-description",
        action="store_true",
        dest="source_description",
        default=False,
        help="Include source descriptions when known",
    )
    parser.add_argument("-g", "--gedcom_in", help="Gedcom input file")
    parser.add_argument("-G", "--gedcom_out", help="Gedcom output file")
    parser.add_argument(
        "-F",
        "--citation-facts",
        action="store_true",
        dest="citation_facts",
        default=False,
        help="Include extracted source citation facts when known",
    )
    parser.add_argument(
        "-I",
        "--include-screenshot-media",
        action="store_true",
        dest="citation_screenshots",
        default=False,
        help="Include media for source citation screenshots",
    )
    parser.add_argument(
        "-K",
        "--keep-apid-tags",
        action="store_true",
        dest="keep_apid",
        default=False,
        help="Keep all _APID tags, filtered out by default",
    )
    parser.add_argument(
        "-l",
        "--logfile",
        dest="logfile",
        default="ancestry_refactor.log",
        help="Optional log file location",
        metavar="FILE",
    )
    parser.add_argument(
        "-o",
        "--overwrite",
        action="store_true",
        dest="overwrite",
        default=False,
        help="Over write output file if it exists",
    )
    parser.add_argument(
        "-p",
        "--clean-places",
        dest="clean_places",
        default=None,
        help="Perform simple place cleanups using mapping file",
        metavar="FILE",
    )
    parser.add_argument(
        "-P",
        "--person-url",
        action="store_true",
        dest="person_url",
        default=False,
        help="Include Ancestry.com person URL when known",
    )
    parser.add_argument(
        "-S",
        "--source-url",
        action="store_true",
        dest="source_url",
        default=False,
        help="Include Ancestry.com source URL when known",
    )
    args = parser.parse_args()

    if not args.base_dir or not args.gedcom_in:
        if not args.config:
            args.config = "ancestry_refactor.toml"

    if args.config:
        if os.path.isfile(args.config):
            with open(args.config, "r") as config_file:
                config_data = toml.load(config_file)
            for key in config_data:
                setattr(args, key, config_data[key])

    if not args.base_dir or not args.gedcom_in:
        print("Base directory and Gedcom input file are required arguments")
        sys.exit(1)
    if not os.path.isdir(args.base_dir):
        print("Base media directory {0} not found".format(args.base_dir))
        sys.exit(1)
    if not os.path.isfile(args.gedcom_in):
        print("Gedcom input file {0} not found".format(args.gedcom_in))
        sys.exit(1)
    if args.clean_places is not None:
        if not os.path.isfile(args.clean_places):
            print("Places file {0} not found".format(args.clean_places))
            sys.exit(1)

    gedcom_file = args.gedcom_in
    media_base = args.base_dir
    if args.gedcom_out:
        new_gedcom_file = args.gedcom_out
    else:
        new_gedcom_file = "{0}/{1}".format(media_base, os.path.basename(gedcom_file))
    if not args.overwrite:
        if os.path.isfile(new_gedcom_file):
            print(
                "New Gedcom file {0} already exists and over write not specified".format(
                    new_gedcom_file
                )
            )
            sys.exit(1)

    log_file = (
        args.base_dir
        + "/logs/"
        + pendulum.now().format("YYYY-MM-DD-HH-MM")
        + "-ancestry-refactor.log"
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-8s %(levelname)-8s %(message)s",
        filename=log_file,
        filemode="w",
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(message)s")
    console.setFormatter(formatter)
    logging.getLogger("").addHandler(console)

    with open(gedcom_file, "r") as gedcom:
        gedcom_data = gedcom.read()

    dbid_queue = Queue()
    dbid_process = Process(target=get_dbid_objects, args=(dbid_queue, media_base))
    dbid_process.start()

    apid_queue = Queue()
    apid_process = Process(target=get_apid_objects, args=(apid_queue, media_base, args))
    apid_process.start()

    guid_queue = Queue()
    guid_process = Process(target=get_guid_objects, args=(guid_queue, media_base))
    guid_process.start()
    guid_map, guid_objects = guid_queue.get()
    guid_process.join()

    if args.clean_places is not None:
        try:
            with open(args.clean_places, "r") as place_file:
                places = toml.load(place_file)
        except:
            logging.error(
                "Error parsing places file %s, may not be valid TOML syntax",
                args.clean_places,
            )
            sys.exit(1)

    dbid_map = dbid_queue.get()
    dbid_process.join()

    apid_image_map, apid_screenshot_map, apid_full_map, apid_objects = apid_queue.get()
    apid_process.join()

    source_queue = Queue()
    source_process = Process(
        target=get_sources,
        args=(source_queue, args, gedcom_data, dbid_map, apid_image_map),
    )
    source_process.start()

    people = get_people_urls(gedcom_data, apid_full_map)

    sources = source_queue.get()
    source_process.join()

    gedcom = open(new_gedcom_file, "w")

    line_number = context_level = 0
    entity = entity_id = media_item = page_text = event_line_text = event_type_text = ""
    source_citation = certificate_number = apid = ""
    in_media = in_source = in_citation = in_event = found_page = False
    media = []
    citation = []
    logging.info("Refactoring Gedcom data")
    for line in gedcom_data.split("\n"):
        line_number = line_number + 1
        if (len(line)) < 5:
            continue
        parts = line.split(" ")
        current_level = parts[0]
        tag = parts[1]
        line = line + "\n"

        if in_event:
            if tag == "TYPE":
                if "OBITUARY" in line.upper():
                    event_type_text = line[7:]
                    line = current_level + " TYPE Obituary\n"
                elif "ARTICLE" in line.upper():
                    event_type_text = line[7:]
                    line = current_level + " TYPE Article\n"
                elif "ANNIVERSARY" in line.upper():
                    event_type_text = line[7:]
                    line = current_level + " TYPE Anniversary\n"
                elif "DEATH NOTICE" in line.upper():
                    event_type_text = line[7:]
                    line = current_level + " TYPE Death Notice\n"
                elif "FUNERAL NOTICE" in line.upper():
                    event_type_text = line[7:]
                    line = current_level + " TYPE Funeral Notice\n"
                elif (
                    "NATURALIZATIONPETITION" in line.upper()
                    or "NATURALIZATION PETITION" in line.upper()
                ):
                    line = (
                        current_level
                        + " TYPE Naturalization: Petition for Naturalization\n"
                    )
                elif "NATURALIZATIONOATHOFALLEGIANCE" in line.upper():
                    line = current_level + " TYPE Naturalization: Oath of Allegiance\n"
                elif "NATURALIZATIONDECLARATION" in line.upper():
                    line = (
                        current_level
                        + " TYPE Naturalization: Declaration of Intention\n"
                    )
                elif "NATURALIZED" in line.upper():
                    line = current_level + " TYPE Naturalization\n"
                elif "NATURALIZATION: DECLARATION OF INTENT" in line.upper():
                    line = (
                        current_level
                        + " TYPE Naturalization: Declaration of Intention\n"
                    )
            if tag in ["NOTE", "SOUR", "OBJE"]:
                if event_line_text != "":
                    if args.event_description:
                        event_line_text = "Description: " + event_line_text
                    emit_line(
                        gedcom, "{0} NOTE {1}".format(current_level, event_line_text)
                    )
                    event_line_text = ""
                if event_type_text != "":
                    if args.event_description:
                        event_type_text = "Description: " + event_type_text
                    emit_line(
                        gedcom, "{0} NOTE {1}".format(current_level, event_type_text)
                    )
                    event_type_text = ""
            if current_level <= context_level:
                if event_line_text != "":
                    if args.event_description:
                        event_line_text = "Description: " + event_line_text
                    emit_line(
                        gedcom, "{0} NOTE {1}".format(current_level, event_line_text)
                    )
                    event_line_text = ""
                if event_type_text != "":
                    if args.event_description:
                        event_type_text = "Description: " + event_type_text
                    emit_line(
                        gedcom, "{0} NOTE {1}".format(current_level, event_type_text)
                    )
                    event_type_text = ""
                in_event = False

        if in_source and current_level <= context_level:
            if entity_id in sources:
                for item in sources[entity_id]:
                    if "0 @S" not in item:
                        emit_line(gedcom, "{0}\n".format(item))
            in_source = False

        if in_media and current_level <= context_level:
            if media_item != "":
                emit_line(gedcom, "{0}\n".format(media_item))
            else:
                for item in media:
                    emit_line(gedcom, item)
            in_media = False
            media_item = ""
            media = []

        if in_citation and current_level <= context_level:
            if found_page:
                emit_line(gedcom, page_text)
            elif args.citation_page:
                if certificate_number != "":
                    if core_event_date != "" or core_event_place != "":
                        page_text = "{0} PAGE ".format(int(context_level) + 1)
                        if core_event_place != "":
                            page_text = "{0}{1}; ".format(page_text, core_event_place)
                        if core_event_date != "":
                            page_text = "{0}{1}; ".format(page_text, core_event_date)
                        page_text = "{0}Certificate: {1}\n".format(
                            page_text, certificate_number
                        )
                        emit_line(gedcom, page_text)
                    elif source_citation != "":
                        if certificate_number not in source_citation:
                            source_citation = "{0}, Certificate: {1}\n".format(
                                source_citation.strip(), certificate_number
                            )
                        emit_line(
                            gedcom,
                            "{0} PAGE {1}\n".format(
                                int(context_level) + 1, source_citation
                            ),
                        )
                elif license_number != "":
                    if core_event_date != "" or core_event_place != "":
                        page_text = "{0} PAGE ".format(int(context_level) + 1)
                        if core_event_place != "":
                            page_text = "{0}{1}; ".format(page_text, core_event_place)
                        if core_event_date != "":
                            page_text = "{0}{1}; ".format(page_text, core_event_date)
                        page_text = "{0}License: {1}\n".format(
                            page_text, license_number
                        )
                        emit_line(gedcom, page_text)
                    elif source_citation != "":
                        if license_number not in source_citation:
                            source_citation = "{0}, License: {1}\n".format(
                                source_citation.strip(), license_number
                            )
                        emit_line(
                            gedcom,
                            "{0} PAGE {1}\n".format(
                                int(context_level) + 1, source_citation
                            ),
                        )
                elif source_citation != "":
                    emit_line(
                        gedcom,
                        "{0} PAGE {1}\n".format(
                            int(context_level) + 1, source_citation
                        ),
                    )

            for item in citation:
                emit_line(gedcom, item)
            if args.keep_apid and apid != "":
                emit_line(
                    gedcom, "{0} _APID {1}\n".format(int(context_level) + 1, apid)
                )
                apid = ""
            in_citation = False

        if tag == "HEAD":
            entity = tag
        elif "@" in tag:
            emit_line(gedcom, line)
            entity = parts[2]
            entity_id = tag
            if entity == "SOUR":
                in_source = True
                context_level = current_level
            if args.person_url in ["WWW", "URL", "_URL", "NOTE"] and entity == "INDI":
                if entity_id in people:
                    emit_line(
                        gedcom,
                        "{0} {1} {2}\n".format(
                            int(current_level) + 1, args.person_url, people[entity_id]
                        ),
                    )
            continue
        elif tag == "PLAC":
            if args.clean_places is not None:
                line = clean_place(line, places)
        elif tag == "DATE":
            if args.clean_dates:
                line = clean_date(line)
        elif tag == "OBJE":
            if "@" not in line:
                in_media = True
                context_level = current_level
        elif tag == "SOUR":
            in_citation = True
            context_level = current_level
            found_page = False
            citation = []
            page_text = (
                source_citation
            ) = certificate_number = license_number = collection = apid = ""
            core_event_type = core_event_date = core_event_place = ""
            emit_line(gedcom, line)
            continue
        elif tag in [
            "BIRT",
            "CHR",
            "DEAT",
            "BURI",
            "CREM",
            "ADOP",
            "BAPM",
            "BARM",
            "BASM",
            "BLES",
            "CHRA",
            "CONF",
            "FCOM",
            "ORDN",
            "NATU",
            "EMIG",
            "IMMI",
            "CENS",
            "PROB",
            "WILL",
            "GRAD",
            "RETI",
            "ANUL",
            "DIV",
            "DIVF",
            "ENGA",
            "MARB",
            "MARC",
            "MARR",
            "MARL",
            "MARS",
            "RESI",
            "EVEN",
        ]:
            in_event = True
            context_level = current_level
            if len(line.strip()) > (len(tag) + 3):
                offset = len(tag) + 3
                event_line_text = line[offset:]
                emit_line(gedcom, "{0}\n".format(line[:offset]))
                continue

        if in_media:
            if tag == "FILE":
                if "http" in line and "guid=" in line:
                    guid = line.split("&").pop(1).split("=").pop(1)
                    if guid in guid_map:
                        media_item = "{0} OBJE {1}".format(
                            context_level, guid_map[guid]
                        )
            media.append(line)
            continue

        if in_citation:
            if tag == "_APID":
                apid = parts[2]
                dbid = apid.split(",")[1].split(":")[0]
                if apid in apid_full_map:
                    apid_data = apid_full_map[apid]
                    if "citation" in apid_data:
                        source_citation = apid_data["citation"]
                    if dbid in dbid_map and "title" in dbid_map[dbid]:
                        collection = dbid_map[dbid]["title"]
                        for key in ["Birth", "Death", "Marriage", "Divorce"]:
                            if key in collection:
                                core_event_type = key
                                break
                    if "facts" in apid_data and len(apid_data["facts"]) > 0:
                        facts = apid_data["facts"]
                        citation.append("{0} DATA\n".format(current_level))
                        first = True
                        core_dates = []
                        core_places = []
                        if core_event_type != "":
                            core_dates = ["{0} Date".format(core_event_type)]
                            core_places = ["{0} Place".format(core_event_type)]
                            if core_event_type == "Divorce":
                                core_dates.append("Decree Date")
                                core_places.append("County of Decree")
                            if core_event_type == "Marriage":
                                core_dates.append("Marriage License Date")
                                core_places.append("Marriage License Place")
                        for fact in facts:
                            fact_data = facts[fact]
                            if args.clean_dates and "Date" in fact:
                                fact_data = clean_date(fact_data).strip()
                            if args.citation_facts:
                                if first:
                                    first = False
                                    note = build_note(
                                        "{0}: {1}".format(fact, fact_data),
                                        level=int(current_level) + 1,
                                        keyword="TEXT",
                                    )
                                else:
                                    note = build_note(
                                        "{0}: {1}".format(fact, fact_data),
                                        level=int(current_level) + 2,
                                        keyword="CONT",
                                    )
                                for item in note:
                                    citation.append("{0}\n".format(item))
                            if "Certificate" in fact:
                                certificate_number = fact_data
                                if (
                                    page_text != ""
                                    and certificate_number not in page_text
                                ):
                                    page_text = "{0}, Certificate: {1}\n".format(
                                        page_text.strip(), certificate_number
                                    )
                            if "License" in fact:
                                license_number = fact_data
                                if page_text != "" and license_number not in page_text:
                                    page_text = "{0}, License: {1}\n".format(
                                        page_text.strip(), license_number
                                    )
                            for check_text in core_dates:
                                if check_text in fact:
                                    core_event_date = "{0}: {1}".format(fact, fact_data)
                                    break
                            for check_text in core_places:
                                if check_text in fact:
                                    core_event_place = "{0}: {1}".format(
                                        fact, fact_data
                                    )
                                    break
                    if args.citation_url and "url" in apid_data:
                        citation.append(
                            "{0} NOTE {1}\n".format(current_level, apid_data["url"])
                        )
                elif args.citation_url:
                    indiv = apid.split(",").pop(0)
                    dbrecord = apid.split(":").pop(2)
                    url = "https://search.ancestry.com/cgi-bin/sse.dll?indiv={0}&dbid={1}&h={2}".format(
                        indiv, dbid, dbrecord
                    )
                    citation.append("{0} NOTE {1}\n".format(current_level, url))
                if apid in apid_image_map:
                    citation.append(
                        "{0} OBJE {1}\n".format(current_level, apid_image_map[apid])
                    )
                if args.citation_screenshots and apid in apid_screenshot_map:
                    citation.append(
                        "{0} OBJE {1}\n".format(
                            current_level, apid_screenshot_map[apid]
                        )
                    )
                if dbid in dbid_map and "title" in dbid_map[dbid]:
                    collection = dbid_map[dbid]["title"]
                continue
            if tag == "PAGE":
                page_text = line
                found_page = True
                continue
            citation.append(line)
            continue

        if tag == "TRLR":
            for guid_object in guid_objects:
                for item in guid_objects[guid_object]:
                    emit_line(gedcom, "{0}\n".format(item))
            for apid_object in apid_objects:
                first = ""
                if args.citation_screenshots:
                    first = None
                for item in apid_objects[apid_object]:
                    if first is None:
                        emit_line(gedcom, "{0}\n".format(item))
                        continue
                    if first == "":
                        first == item
                        continue
                    if "FILE" in item and "apid_" in item and "png" in item:
                        break
                    emit_line(gedcom, "{0}\n".format(first))
                    emit_line(gedcom, "{0}\n".format(item))
                    first = None

        if not in_source:
            emit_line(gedcom, line)
    gedcom.flush()
    gedcom.close()
    logging.info("Gedcom refactoring completed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Starting application shutdown")
        sys.exit(1)
    sys.exit(0)
