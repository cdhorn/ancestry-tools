#!/usr/bin/env python3
"""
##############################################################################
# Copyright 2019-2020 Christopher Horn
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
import atexit
import filecmp
import hashlib
import json
import logging
import os
import sys
import time
from multiprocessing import Process, Queue
from optparse import SUPPRESS_HELP, OptionParser
from signal import SIGABRT, SIGTERM, signal

import filetype
import pathvalidate
import pendulum
import requests
import toml
from bs4 import BeautifulSoup
from selenium.common.exceptions import WebDriverException
from selenium.webdriver import Firefox, FirefoxProfile
from selenium.webdriver.firefox.options import Options

_SIGNAL_EXIT = False


def clean_exit():
    """
    Exits cleanly
    """
    global _SIGNAL_EXIT
    _SIGNAL_EXIT = True
    sys.exit(0)


def session_cleanup(session):
    """
    Perform clean session shutdown saving current state
    """
    logging.info("Starting application shutdown")
    try:
        state = {
            "checkpoint": session.checkpoint,
            "tree_id": session.tree_id,
            "tree_name": session.tree_name,
            "unavailable": session.unavailable,
        }
        with open(session.options.output + "/metadata/state.toml", "w") as state_file:
            state_file.write(toml.dumps(state))
            state_file.flush()
    except:
        pass

    logging.info("Cleaning up session and closing browser if active")
    logging.getLogger().setLevel(logging.CRITICAL)
    if _SIGNAL_EXIT:
        try:
            session.save_screenshot("ancestryAbortImage.png")
        except:
            logging.critical("Failed to save abort screen shot")
    try:
        session.quit()
    except:
        pass
    logging.getLogger().setLevel(logging.INFO)


def load_tables(queue, path):
    """
    Load image hash and identifier caches
    """
    checkpoint = 0
    unavailable = []
    tree_id = tree_name = ""
    hash_map = {}
    logging.info("Checking for hashes to seed image hash cache")
    for dir_name in ["apid", "guid"]:
        for fs_entry in os.scandir("{0}/metadata/{1}".format(path, dir_name)):
            if fs_entry.is_file() and ".toml" in fs_entry.name:
                with open(fs_entry.path, "r") as meta_file:
                    metadata = toml.load(meta_file)
                if "hash" in metadata and "image" in metadata:
                    hash_map.update({metadata["hash"]: metadata["image"]})
                if "clip_hash" in metadata and "clipping" in metadata:
                    hash_map.update({metadata["clip_hash"]: metadata["clipping"]})

    state_file = "{0}/metadata/state.toml".format(path)
    if os.path.isfile(state_file):
        with open(state_file, "r") as meta_file:
            metadata = toml.load(meta_file)
        if "checkpoint" in metadata:
            checkpoint = metadata["checkpoint"]
        if "tree_id" in metadata:
            tree_id = metadata["tree_id"]
        if "tree_name" in metadata:
            tree_name = metadata["tree_name"]
        if "unavailable" in metadata:
            unavailable = metadata["unavailable"]
    if hash_map != {}:
        logging.info("Loaded %d image hashes", len(hash_map))
    else:
        logging.info("No hashes found to preseed cache")

    image_cache = {}
    logging.info("Checking for images to seed image identifier cache")
    for fs_object in os.scandir("{0}/media/dbid".format(path)):
        if fs_object.is_dir():
            for fs_entry in os.scandir(fs_object.path):
                if fs_entry.is_file():
                    dbid = fs_object.name
                    extension = fs_entry.name.split(".").pop(-1)
                    iid = fs_entry.name.replace("." + extension, "")
                    image_cache.update({"{0}_{1}".format(dbid, iid): fs_entry.path})
    if image_cache != []:
        logging.info("Loaded %d image identifiers", len(image_cache))
    else:
        logging.info("No images found to preseed cache")

    result = {
        "checkpoint": checkpoint,
        "tree_id": tree_id,
        "tree_name": tree_name,
        "unavailable": unavailable,
        "hash_map": hash_map,
        "image_cache": image_cache,
    }
    queue.put(result)


def load_gedcom(queue, gedcom_data):
    """
    First pass load for gedcom data
    """
    people = {}
    person = ""
    families = 0
    apids = []
    guids = []
    apid_total = guid_total = 0
    logging.info("Starting first pass extracting Gedcom data")
    for line in gedcom_data.split("\n"):
        if len(line) < 6:
            continue
        tag = line.split(" ")[1]
        if "@P" in tag:
            person = tag
            continue
        if tag == "NAME" and person != "":
            people.update({person: line[7:]})
            continue
        if "@F" in tag:
            families = families + 1
            continue
        if tag == "_APID":
            apid_total = apid_total + 1
            apid = line.split(" ")[2]
            if apid not in apids:
                apids.append(apid)
            continue
        if tag == "FILE" and "http" in line:
            guid_total = guid_total + 1
            url = line.split(" ").pop(2).strip()
            guid = url.split("&").pop(1)[5:]
            if guid not in guids:
                guids.append(guid)

    result = {
        "people": people,
        "families": families,
        "apid_total": apid_total,
        "apid_unique": len(apids),
        "guid_total": guid_total,
        "guid_unique": len(guids),
    }
    queue.put(result)


def wait_for_text(session, text, timeout):
    """
    Poll until expected text appears in an asynchronously loading page
    """
    count = 0
    limit = timeout / 0.2
    test_text = text.split("|")
    while True:
        for text in test_text:
            if text == None:
                return "unavailable"
            if session.page_source == None:
                return "unavailable"
            if text in session.page_source:
                return "ready"
        if "this page is temporarily unavailable" in session.page_source:
            return "unavailable"
        if count > limit:
            logging.error("Timeout waiting for object visibility")
            return "timeout"
        count = count + 1
        time.sleep(0.2)


def login(session):
    """
    Handle initial login process
    """
    try:
        session.get("{0}/secure/Login".format(session.options.ancestry))
    except:
        logging.error("Problem loading initial Ancestry.com login page")
        session.save_screenshot("ancestryFailedConnectImage.png")
        sys.exit(1)

    if 'id="signInCustLink"' in session.page_source:
        logging.info("Found sign in screen, clicking link to sign in")
        sign_in = session.find_element_by_id("signInCustLink")
        sign_in.click()
        session.switch_to.default_content()
        result = wait_for_text(session, 'id="usernameLabel"', 10)
        if result != "ready":
            logging.error("Login page did not come up after clicking sign in")
            session.save_screenshot("ancestryFailedSignInClick.png")
            sys.exit(1)

    if 'id="signInFrame"' in session.page_source:
        iframe = session.find_element_by_id("signInFrame")
        session.switch_to.frame(iframe)

    if 'id="usernameLabel"' in session.page_source:
        logging.info("Attempting login as %s", session.options.username)
        submit_id = "signInBtn"
        user_id = "username"
        pass_id = "password"
        if 'id="usernameHOM"' in session.page_source:
            submit_id = "signinHOM"
            user_id = "usernameHOM"
            pass_id = "passwordHOM"
        if submit_id not in session.page_source:
            logging.error("Can not find submit button to login")
            session.save_screenshot("ancestryMissingLoginSubmit.png")
            sys.exit(1)

        account_field = session.find_element_by_id(user_id)
        account_field.clear()
        account_field.send_keys(session.options.username)

        password_field = session.find_element_by_id(pass_id)
        password_field.clear()
        password_field.send_keys(session.options.password)

        submit_button = session.find_element_by_id(submit_id)
        submit_button.click()

    session.switch_to.default_content()

    count = 0
    logged_in = False
    while count < 100:
        try:
            if "About this tree" in session.page_source:
                logged_in = True
                break
            if "Products and Services" in session.page_source:
                logged_in = True
                break
            if "Invalid credentials" in session.page_source:
                logging.error("Login failed, invalid credentials supplied")
                session.save_screenshot("ancestryFailedLoginImage.png")
                sys.exit(1)
        except:
            pass
        count = count + 1
        time.sleep(0.2)

    if not logged_in:
        logging.error("Login failed, home page did not appear to load")
        session.save_screenshot("ancestryFailedLoginImage.png")
        sys.exit(1)

    soup = BeautifulSoup(session.page_source, features="lxml")
    full_name = soup.find(id="navAccountUsername").text
    logging.info("Successfully logged in as %s", full_name)
    session.options.full_name = full_name


def compare_files(file1, file2):
    """
    Compare 2 files, separated out as a function to allow for different methods for file types
    """
    if file1[-3:] == "pdf" or file2[-3:] == "pdf":
        # PDF hashes change in unpredictable ways.
        # There are some tools that convert pdfs to images and then compare them
        #   but they add a lot of overhead and could be more difficult to setup.
        # This works well enough for now.
        # If the file sizes are within a few bytes and they have the same name
        return abs(int(os.stat(file1).st_size) - int(os.stat(file2).st_size)) < 8
    else:
        return filecmp.cmp(file1, file2)


def get_image(session, url, target_name):
    """
    Download and validate not a duplicate image
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        + "(KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    }

    target_name = pathvalidate.sanitize_filepath(target_name)

    download_name = "{0}/download.data".format(os.path.dirname(target_name))
    if os.path.isfile(download_name):
        logging.debug("Found and removing old %s", download_name)
        os.remove(download_name)

    logging.info("Downloading image at %s", url)

    download_session = requests.session()
    download_session.headers.update(headers)
    for cookie in session.get_cookies():
        download_session.cookies.update({cookie["name"]: cookie["value"]})

    try:
        file_data = download_session.get(url, allow_redirects=True)
        logging.debug(download_name)
        path, filename = os.path.split(download_name)
        os.makedirs(path, exist_ok=True)
        with open(download_name, "wb") as image_file:
            image_file.write(file_data.content)
    except:
        logging.error("Error downloading file, retrying")
        time.sleep(1)
        file_data = download_session.get(url, allow_redirects=True)
        with open(download_name, "wb") as image_file:
            image_file.write(file_data.content)
    file_type = filetype.guess(file_data.content)

    if not file_type:
        if b"this page is lost or can" in file_data.content:
            logging.error(
                "Newspapers.com Intermittent Failure, Flagged as unavailable: {}".format(
                    url
                )
            )
        else:
            logging.error("No file returned. Flagged as unavailable: {}".format(url))
        return None, None, False

    hash_data = hashlib.sha256()
    hash_data.update(file_data.content)
    file_hash = hash_data.hexdigest()
    del hash_data
    del file_data
    del download_session

    if file_hash in session.hash_map:
        if os.path.isfile(session.hash_map[file_hash]):
            if compare_files(download_name, session.hash_map[file_hash]):
                logging.info(
                    "Downloaded image identical to %s", session.hash_map[file_hash]
                )
                os.remove(download_name)
                return session.hash_map[file_hash], file_hash, True
            logging.critical(
                "Downloaded image hash identical to %s", session.hash_map[file_hash]
            )
            logging.critical(
                "But a binary file compare differs! You should play the lottery!"
            )
            logging.critical("Processing aborted as no clue what to do...")
            sys.exit(1)

    loop = 1
    file_name = "{0}.{1}".format(target_name, file_type.extension)

    while os.path.isfile(file_name):
        logging.debug("Found existing %s", file_name)
        if compare_files(download_name, file_name):
            logging.info("Downloaded image identical to %s", file_name)
            os.remove(download_name)
            return file_name, file_hash, False
        file_name = "{0}-{1}.{2}".format(target_name, loop, file_type.extension)
        loop = loop + 1

    os.replace(download_name, file_name)
    logging.info("Resulting image named %s", os.path.basename(file_name))

    session.hash_map.update({file_hash: file_name})
    return file_name, file_hash, False


def get_screenshot(session, target_name):
    """
    Take element screenshot
    """

    # Some names from Ancestry can include characters that don't play well with the file system
    target_name = pathvalidate.sanitize_filepath(target_name)

    if os.path.isfile(target_name):
        logging.info("Found existing screenshot of source page")
        return target_name

    logging.info("Taking screenshot of source page")
    element = session.find_element_by_class_name("article.ancCol.w66")
    element.screenshot(target_name)
    return target_name


def ancestry_media(session, line):
    """
    Process an ancestry media item uniquely identified by the _APID field
    """
    apid = line.split(" ").pop(2).strip()
    indiv = apid.split(",").pop(0)
    dbid = apid.split(",").pop(1).split(":").pop(0)
    dbrecord = apid.split(":").pop(2)
    apid_meta_file = "{0}/metadata/apid/apid_{1}_{2}_{3}.toml".format(
        session.options.output, indiv, dbid, dbrecord
    )
    if os.path.isfile(apid_meta_file):
        process_data = False
        try:
            with open(apid_meta_file, "r") as meta_file:
                metadata = toml.load(meta_file)
            if "image" in metadata:
                if not os.path.isfile(metadata["image"]):
                    process_data = True
            if session.options.screenshot and metadata["type"] != "rawimage":
                if "screenshot" not in metadata:
                    process_data = True
                elif not os.path.isfile(metadata["screenshot"]):
                    process_data = True
        except:
            process_data = True
        if not process_data:
            if session.line_number > session.checkpoint:
                logging.debug("APID %s record already processed", apid)
            return "duplicate"
        logging.info(
            "APID %s previously processed but image missing so reprocessing", apid
        )

    if apid in session.unavailable:
        if session.line_number > session.checkpoint:
            logging.debug("APID %s record duplicate of an unavailable one", apid)
        return "skip"

    logging.info("Processing APID %s", apid)
    item_start_time = pendulum.now()

    dbid_data = {"dbid": dbid}
    apid_data = {"apid": apid}
    apid_data.update(
        {
            "url": "https://search.ancestry.com/cgi-bin/sse.dll?indiv={0}&dbid={1}&h={2}".format(
                indiv, dbid, dbrecord
            )
        }
    )
    logging.info("Fetching source record page at %s", apid_data["url"])
    session.get(apid_data["url"])

    if session.current_url != apid_data["url"]:
        source_type = "rawimage"
    else:
        result = wait_for_text(session, "personRecordSavedToText", 10)
        if result != "ready":
            logging.warning("Source page for APID %s unavailable or timed out", apid)
            if result == "unavailable":
                session.unavailable = session.unavailable + [apid]
            return result
        if 'id="viewOriginal"' in session.page_source:
            source_type = "image"
        elif "Go to website" in session.page_source:
            source_type = "url"
        else:
            source_type = "text"
    logging.info("Source appears to be a %s based record", source_type)
    apid_data.update({"type": source_type})

    logging.info("Extracting facts and source information")
    soup = BeautifulSoup(session.page_source, features="lxml")

    title_section = soup.find(id="recordIndexPageTitle")
    if title_section is None:
        title_section = soup.find(class_="collectionTitle")
    if title_section is not None:
        page_title = title_section.text.replace("\n\nfor", "").strip()
        subtitle_section = soup.find(class_="pageIntro")
        if subtitle_section is not None:
            subtitle_entry = subtitle_section.find("a")
            if subtitle_entry is not None:
                db_title = subtitle_entry.text.strip()
                dbid_data.update({"title": db_title})
                apid_data.update(
                    {"title": "{0} in the {1}".format(page_title, db_title)}
                )
            else:
                subtitle_section = None
        if subtitle_section is None:
            dbid_data.update({"title": page_title})
            apid_data.update({"title": page_title})

    person_section = soup.find(class_="personRecordSavedToText")
    if person_section is not None:
        person_entry = person_section.find("a")
        if person_entry is not None:
            apid_data.update(
                {"person_name": person_entry.text, "person_url": person_entry["href"]}
            )
            session.tree_id = person_entry["href"].split("tid=").pop(1)
            tree_record = soup.find(class_="tree_recordSavedTo")
            if tree_record is not None:
                session.tree_name = tree_record.text.strip('"')

    record_section = soup.find(id="recordData")
    if record_section is not None:
        facts = {}
        for row in record_section.find_all("tr"):
            table_th = row.find("th", string=True)
            if table_th is not None:
                key = table_th.string.strip(" :\n")
            table_td = row.find("td", string=True)
            if table_td is not None:
                value = table_td.text.replace("\u00a0", " ").strip(" \n")
                if (
                    "#viewNeighbors" in value
                    or "#mapWrapper" in value
                    or "Search for" in value
                ):
                    continue
                value = (
                    value.replace("\n\n", "; ").replace(" ;", " ").replace("\n", " ")
                )
                while "  " in value:
                    value = value.replace("  ", " ")
                value = value.replace("Name Age; ", "")
                if key.lower() == "url":
                    value = table_td.find(class_="link")["href"]
                facts.update({key: value})
        if facts != {}:
            apid_data.update({"facts": facts})

    citation_section = soup.find(id="sourceCitation")
    if citation_section is not None:
        for citation in citation_section.find_all(class_="citationCon"):
            section_title = citation.find(class_="citationTitle")
            if section_title is not None:
                section_title = section_title.text.strip(" ").lower().replace(" ", "_")
                section_text = citation.find(class_="sourceText")
                if section_text is not None:
                    data = section_text.text.strip(" \n").replace(" Learn more...", "")
                    data = (
                        data.replace(".\n ", "; ")
                        .replace("\u2019", "'")
                        .replace("\n", " ")
                    )
                    while "  " in data:
                        data = data.replace("  ", " ")
                    if section_title == "source_information":
                        dbid_data.update(
                            {
                                "publisher": data.split("Original data:")
                                .pop(0)
                                .strip(" ;,")
                            }
                        )
                        if "Original data:" in data:
                            dbid_data.update(
                                {
                                    "original": data.split("Original data:")
                                    .pop(1)
                                    .strip(" ;,")
                                }
                            )
                    elif section_title == "description":
                        dbid_data.update({"description": data})
                    elif section_title == "source_citation":
                        apid_data.update({"citation": data})

    if session.options.screenshot and source_type != "rawimage":
        screenshot_file = "{0}/media/apid/apid_{1}_{2}_{3}.png".format(
            session.options.output, indiv, dbid, dbrecord
        )
        get_screenshot(session, screenshot_file)
        apid_data.update({"screenshot": screenshot_file})

    if source_type in ["image", "rawimage"]:
        file_name = file_hash = ""
        if source_type == "image":
            image_link = soup.find(class_="photo", href=True)["href"]
        else:
            image_link = session.current_url
        logging.debug("Image link: %s", image_link)
        if "ancestry.com/imageviewer" in image_link:
            image_id = image_link.split("?").pop(0).split("/").pop(-1)
            unique_id = dbid + "_" + image_id
            if unique_id in session.images:
                logging.info("Image already downloaded")
                for file_hash in session.hash_map:
                    if image_id in session.hash_map[file_hash]:
                        file_name = session.hash_map[file_hash]
                        break
                if file_name == "":
                    file_name = session.images[unique_id]
                    hash_data = hashlib.sha256()
                    with open(file_name, "rb") as image_file:
                        file_data = image_file.read()
                    hash_data.update(file_data)
                    file_hash = hash_data.hexdigest()
                    session.hash_map.update({file_hash: file_name})
            else:
                logging.info("Getting image meta data")
                image_dir = "{0}/media/dbid/{1}".format(session.options.output, dbid)
                if not os.path.isdir(image_dir):
                    os.makedirs(image_dir)
                image_file = "{0}/{1}".format(image_dir, image_id)

                image_meta_link = (
                    "https://www.ancestry.com/imageviewer/api/media/token?"
                    + "dbId={0}&imageId={1}".format(dbid, image_id)
                )
                logging.debug("Image metadata link: %s", image_meta_link)
                session.get(image_meta_link)

                result = wait_for_text(session, "imageDownloadUrl", 10)
                if result != "ready":
                    logging.error("Page unavailable or timeout loading image metadata")
                    return result

                download_url = ""
                try:
                    soup = BeautifulSoup(session.page_source, features="lxml")
                    image_meta_data = json.loads(soup.find(id="json").string)
                    download_url = image_meta_data["imageDownloadUrl"]
                except Exception:
                    logging.debug(session.page_source)
                    logging.error('Unable to find image download URL')
                    
                if download_url in [None, ""]:
                    logging.error("Unable to find image download URL")
                    return "timeout"

                logging.debug("Image download url: %s", download_url)
                file_name, file_hash, duplicate = get_image(
                    session, download_url, image_file
                )
            if file_name:
                session.images.update({unique_id: file_name})
        if file_name != "":
            apid_data.update({"image": file_name, "hash": file_hash})

    with open(apid_meta_file, "w") as meta_file:
        meta_file.write(toml.dumps(apid_data))
        meta_file.flush()

    dbid_meta_file = "{0}/metadata/dbid/{1}.toml".format(session.options.output, dbid)
    if not os.path.isfile(dbid_meta_file):
        if "publisher" not in dbid_data:
            db_page = "https://www.ancestry.com/search/collections/{0}".format(dbid)
            logging.info("Fetching database search page at %s", db_page)
            session.get("https://www.ancestry.com/search/collections/{0}".format(dbid))
            result = wait_for_text(session, "sourceInformation", 10)
            if result == "ready":
                logging.info("Checking for database publisher information")
                soup = BeautifulSoup(session.page_source, features="lxml")
                source_information = soup.find(id="sourceInformation")
                data = source_information.find(class_="conBody")
                data = data.text.strip(" \n").replace(" Learn more...", "")
                data = (
                    data.replace(".\n ", "; ").replace("\u2019", "'").replace("\n", " ")
                )
                while "  " in data:
                    data = data.replace("  ", " ")
                dbid_data.update(
                    {"publisher": data.split("Original data:").pop(0).strip(" ;,")}
                )
                if "Original data:" in data:
                    dbid_data.update(
                        {"original": data.split("Original data:").pop(1).strip(" ;,")}
                    )
        with open(dbid_meta_file, "w") as meta_file:
            meta_file.write(toml.dumps(dbid_data))
            meta_file.flush()

    item_process_time = pendulum.now() - item_start_time
    logging.info("Item processing time %d seconds", item_process_time.seconds)
    return "success"


def get_newspaper_clipping(session, url):
    """
    Download newspapers.com clippings as pdfs with source info
    (the default images of these clippings are low quality but anyone can download higher quality clippings without a login)

    Download format
    https://www.newspapers.com/clippings/download/?id=55922467

    Note format from GEDCOM (This is what the script looks for)
    https://www.newspapers.com/clip/55922467/shareholders-meeting/
    """

    cid = url.split("/").pop(4)
    base_name = "newspapers_com--{0}--{1}".format(url.split("/").pop(5), cid)
    dl_url = "https://www.newspapers.com/clippings/download/?id={}".format(cid)

    logging.info(
        "Fetching Newspapers.com clipping: {0} at {1}".format(
            url.split("/").pop(5), dl_url
        )
    )

    image_dir = "{0}/media/{1}".format(session.options.output, "clippings")
    if not os.path.isdir(image_dir):
        os.makedirs(image_dir)
    image_name = "{0}/{1}".format(image_dir, base_name)

    file_name, file_hash, duplicate = get_image(session, dl_url, image_name)
    if not duplicate and file_name:
        return {"clipping": file_name, "clip_hash": file_hash}
    return {}


def check_url_note(url, metadata):
    """
    Checks the url note for urls that can be processed for additional files
    Initially this is just newspaper.com clippings.

    Returns True if the url needs to be processed, false if it doesn't
    """
    # The check value and the toml value
    check_dict = {"https://www.newspapers.com/clip/": "clipping"}
    for check_value in check_dict:
        if check_value in url:
            if check_dict[check_value] in metadata:
                if not os.path.isfile(metadata[check_dict[check_value]]):
                    return True
                else:
                    continue
            else:
                return True
    return False


def process_url_note(session, url):
    """
    Processes a url note, downloads any additional files and returns a dict to update the metadata guid
    """
    # Dict contains a simple lookup string and the corrisponding function if it is found
    check_dict = {
        "https://www.newspapers.com/clip/": {"function": get_newspaper_clipping}
    }
    result = ""
    for check_value in check_dict:
        if check_value in url:
            # Can only match one of the check_dict options so it returns after the first match
            result = check_dict[check_value]["function"](session, url)
            if result:
                return result
    return {}


def user_media(session, line, url_note):
    """
    Process an ancestry user contributed media item uniquely identified by the GUID
    """
    url = line.split(" ").pop(2).strip()
    guid = url.split("&").pop(1)[5:]
    guid_meta_file = "{0}/metadata/guid/{1}.toml".format(session.options.output, guid)

    if os.path.isfile(guid_meta_file):
        process_data = False
        try:
            with open(guid_meta_file, "r") as meta_file:
                metadata = toml.load(meta_file)
            if "image" in metadata:
                if not os.path.isfile(metadata["image"]):
                    process_data = True

            if check_url_note(url_note, metadata):
                process_data = True

        except Exception as e:
            process_data = True

        if not process_data:
            if session.line_number > session.checkpoint:
                logging.debug("GUID indicates user media item already downloaded")
            return "duplicate"
        logging.info("GUID previously processed but image missing so reprocessing")

    if guid in session.unavailable:
        if session.line_number > session.checkpoint:
            logging.debug(
                "GUID indicates user media item duplicate of unavailable item"
            )
        return "skip"

    item_start_time = pendulum.now()
    logging.info("Fetching image media page at %s", url)
    session.get(url)

    result = wait_for_text(session, "showOriginalLink", 10)
    if result != "ready":
        if result == "unavailable":
            session.unavailable = session.unavailable + [guid]
        return result

    soup = BeautifulSoup(session.page_source, features="lxml")
    image_link = soup.find(id="showOriginalLink")["href"]

    logging.info("Extracting metadata for the image media")
    edit_object = session.find_element_by_id("editObjectLink")
    edit_object.click()

    result = wait_for_text(session, "PictureType", 10)
    if result != "ready":
        logging.error("Page unavailable or timed out loading")
        return result

    soup = BeautifulSoup(session.page_source, features="lxml")
    guid_data = {
        "guid": guid,
        "url": url,
        "type": soup.find(id="PictureType").find(selected="true")["value"],
        "title": soup.find(id="MediaName")["value"],
    }

    facts = {
        "description": soup.find(id="Description").text,
        "location": soup.find(id="Location")["value"],
        "date": soup.find(id="Date")["value"],
    }
    if guid_data["type"] == "document":
        facts.update({"transcription": soup.find(id="DocumentTranscription").text})
    if guid_data["type"] == "headstone":
        facts.update(
            {
                "headstone_name": soup.find(id="HeadstoneName")["value"],
                "headstone_birth_year": soup.find(id="Text2")["value"],
                "headstone_birth_location": soup.find(id="Text3")["value"],
                "headstone_death_year": soup.find(id="Text4")["value"],
                "headstone_death_location": soup.find(id="Text5")["value"],
                "headstone_cemetery_name": soup.find(id="HeadstoneCemeteryName")[
                    "value"
                ],
            }
        )
    guid_data.update({"facts": facts})

    base_name = guid_data["title"].lower()
    if base_name in ["", None]:
        base_name = "untitled"
    for remove_character in [",", "-", '"', "'", "&", ".", "(", ")", "[", "]"]:
        base_name = base_name.replace(remove_character, "")
    base_name = base_name.replace(" ", "_")
    while "__" in base_name:
        base_name = base_name.replace("__", "_")

    image_dir = "{0}/media/{1}".format(session.options.output, guid_data["type"])
    if not os.path.isdir(image_dir):
        os.makedirs(image_dir)
    image_name = "{0}/{1}".format(image_dir, base_name)

    file_name, file_hash, duplicate = get_image(session, image_link, image_name)
    if file_name:
        guid_data.update({"image": file_name, "hash": file_hash})

        guid_data.update(process_url_note(session, url_note))

        with open(guid_meta_file, "w") as meta_file:
            meta_file.write(toml.dumps(guid_data))
            meta_file.flush()

        item_process_time = pendulum.now() - item_start_time
        logging.info("Item processing time %d seconds", item_process_time.seconds)
        if duplicate:
            return "duplicate"
        return "success"
    return "unavailable"


def main():
    """
    Main program
    """
    for signal_type in [SIGTERM, SIGABRT]:
        signal(signal_type, clean_exit)

    parser = OptionParser("usage: %prog [options] accountName password gedcomFile")
    parser.add_option(
        "-c",
        "--count",
        dest="count",
        default="999999",
        help=SUPPRESS_HELP,
        metavar="NUMBER",
    )
    parser.add_option(
        "-i",
        "--ignore",
        action="store_true",
        dest="ignore",
        default=False,
        help="Ignore previously identified unavailable APID entries",
    )
    parser.add_option(
        "-l",
        "--logfile",
        dest="logfile",
        default="ancestry_extract.log",
        help="Optional log file location",
        metavar="FILE",
    )
    parser.add_option(
        "-o",
        "--output",
        dest="output",
        default=".",
        help="Output directory",
        metavar="DIR",
    )
    parser.add_option(
        "-r",
        "--resume",
        action="store_true",
        dest="resume",
        default=False,
        help="Resume if prior state found",
    )
    parser.add_option(
        "-s",
        "--screenshot",
        action="store_true",
        dest="screenshot",
        default=False,
        help="Generate source record screenshots",
    )
    parser.add_option(
        "-u",
        "--url",
        dest="ancestry",
        default="https://www.ancestry.com",
        help="Override default https://www.ancestry.com URL",
    )
    (options, args) = parser.parse_args()

    if len(args) != 3:
        print("Account name, password, and gedcom file are required arguments")
        sys.exit(1)
    if not os.path.isfile(args[2]):
        print("Gedcom file not found")
        sys.exit(1)
    with open(args[2], "r") as gedcom:
        gedcom_data = gedcom.read()
    if (
        "1 SOUR Ancestry.com Family Trees" not in gedcom_data
        or "2 CORP Ancestry.com" not in gedcom_data
    ):
        print("Gedcom file does not appear to be from Ancestry.com")
        sys.exit(1)

    options.username = args[0]
    options.password = args[1]
    options.gedcom = args[2]

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-8s %(levelname)-8s %(message)s",
        filename=options.logfile,
        filemode="a",
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(message)s")
    console.setFormatter(formatter)
    logging.getLogger("").addHandler(console)

    for check_dir in [
        "/media/dbid",
        "/media/apid",
        "/metadata/guid",
        "/metadata/apid",
        "/metadata/dbid",
    ]:
        if not os.path.isdir(options.output + check_dir):
            os.makedirs(options.output + check_dir)

    gedcom_queue = Queue()
    gedcom_process = Process(target=load_gedcom, args=(gedcom_queue, gedcom_data))
    gedcom_process.start()

    cache_queue = Queue()
    cache_process = Process(target=load_tables, args=(cache_queue, options.output))
    cache_process.start()

    logging.info("Launching browser")

    firefox_profile = FirefoxProfile()
    firefox_profile.set_preference("browser.startup.homepage", "about:blank")
    firefox_profile.set_preference("browser.download.folderList", 2)
    firefox_profile.set_preference("browser.download.panel.shown", False)
    firefox_profile.set_preference("browser.download.manager.showWhenStarting", False)
    firefox_profile.set_preference("browser.download.dir", options.output)
    firefox_profile.set_preference(
        "browser.helperApps.neverAsk.saveToDisk", "application/octet-stream"
    )
    firefox_profile.set_preference("places.history.enabled", False)
    firefox_options = Options()
    firefox_options.headless = True
    session = Firefox(options=firefox_options, firefox_profile=firefox_profile)

    atexit.register(session_cleanup, session)
    session.implicitly_wait(15)
    session.fullscreen_window()
    session.options = options
    login(session)

    result = cache_queue.get()
    session.checkpoint = result["checkpoint"]
    session.tree_id = result["tree_id"]
    session.tree_name = result["tree_name"]
    session.unavailable = []
    if options.resume or options.ignore:
        session.unavailable = result["unavailable"]
    session.hash_map = result["hash_map"]
    session.images = result["image_cache"]
    cache_process.join()

    result = gedcom_queue.get()
    people = result["people"]
    people_total = len(people)
    family_total = result["families"]
    apid_total = result["apid_total"]
    apid_unique = result["apid_unique"]
    guid_total = result["guid_total"]
    guid_unique = result["guid_unique"]
    gedcom_process.join()

    logging.info(
        "Found %d people and %d families to process", people_total, family_total
    )
    logging.info(
        "Found %d unique and %d total ancestry media items to process",
        apid_unique,
        apid_total,
    )
    logging.info(
        "Found %d unique and %d total user media items to process",
        guid_unique,
        guid_total,
    )

    print_flag = False
    session.line_number = 0
    success = unavailable = duplicate = skip = timeouts = total = count = 0
    person_number = family_number = 0
    apid_number = guid_number = 0
    person = husband = wife = ""
    url_note = ""
    logging.info("Starting second pass processing Gedcom media items")
    for line in gedcom_data.split("\n"):
        session.line_number = session.line_number + 1
        if options.resume and session.line_number < session.checkpoint:
            continue
        options.resume = False
        if len(line) < 5:
            continue

        if line[0] == 1:
            # reset the url note for new records
            url_note = ""

        tag = line.split(" ")[1]
        if tag == "SOUR":
            if session.line_number > session.checkpoint:
                session.checkpoint = session.line_number
            continue
        if "@P" in tag:
            person_number = person_number + 1
            husband = wife = ""
            person = people[tag]
            print_flag = False
            continue
        if "@F" in tag:
            family_number = family_number + 1
            husband = wife = person = ""
            print_flag = False
            continue
        if tag == "HUSB":
            husband = people[line[7:]]
            continue
        if tag == "WIFE":
            wife = people[line[7:]]
            continue
        if tag == "NOTE":
            if "http" in line:
                url_note = line[7:]
            continue

        if tag in ["FILE", "_APID"]:
            total = total + 1
            if not print_flag:
                if session.line_number > session.checkpoint:
                    if person:
                        logging.info(
                            "Processing records for person %s (%d of %d)",
                            person,
                            person_number,
                            people_total,
                        )
                    else:
                        who = join = ""
                        if husband != "":
                            who = husband
                            join = " and "
                        if wife != "":
                            who = who + join + wife
                        logging.info(
                            "Processing records for family of %s (%d of %d)",
                            who,
                            family_number,
                            family_total,
                        )
                    print_flag = True

            if " FILE " in line and "f=image&guid=" in line:
                guid_number = guid_number + 1
                logging.debug(
                    "User media item %d of %d with %d unique",
                    guid_number,
                    guid_total,
                    guid_unique,
                )
                result = user_media(session, line, url_note)
                url_note = ""
            if " _APID " in line:
                process_apid = True
                if options.ignore:
                    apid = line.split(" ").pop(2).strip()
                    if apid in session.unavailable:
                        process_apid = False
                        result = "unavailable"
                if process_apid:
                    apid_number = apid_number + 1
                    if "::0" not in line:
                        logging.debug(
                            "Ancestry media item %d of %d with %d unique",
                            apid_number,
                            apid_total,
                            apid_unique,
                        )
                        result = ancestry_media(session, line)

            if result == "success":
                count = count + 1
                success = success + 1
            elif result == "duplicate":
                duplicate = duplicate + 1
            elif result == "unavailable":
                if person:
                    logging.info("Unavailable item for %s", person)
                else:
                    logging.info("Unavailable item for %s / %s", husband, wife)
                unavailable = unavailable + 1
            elif result == "timeout":
                timeouts = timeouts + 1
            elif result == "skip":
                skip = skip + 1

            if count == int(options.count):
                logging.info("Reached limit of %d records processed", count)
                break

    logging.info("Total overall records:            %d", total)
    logging.info("Total processed records:          %d", success)
    logging.info("Total duplicate records:          %d", duplicate)
    logging.info("Total unavailable records:        %d", unavailable)
    logging.info("Total skipped due to unavailable: %d", skip)
    logging.info("Total skipped due to timeouts:    %d", timeouts)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Starting application shutdown")
        sys.exit(1)
    sys.exit(0)
