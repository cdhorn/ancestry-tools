#!/usr/bin/env python3
########################################################################
# Copyright 2018 Christopher Horn
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
########################################################################

import logging, sys, os, re, time, json, toml, lxml, pendulum, atexit
import requests, filetype, filecmp, hashlib

from multiprocessing import Process, Queue
from signal import signal, SIGINT, SIGTERM, SIGABRT
from optparse import OptionParser, SUPPRESS_HELP
from bs4 import BeautifulSoup
from urllib import request
from PIL import Image

from selenium.webdriver import Firefox, FirefoxProfile
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import Select

_signalExit = False

def clean_exit(*args):
    global _signalExit
    _signalExit = True
    exit(0)
    
def session_cleanup(session):
    logging.info('Starting application shutdown')
    try:
        state = {'checkpoint': session.checkpoint,
                 'tree_id': session.tree_id,
                 'tree_name': session.tree_name,
                 'unavailable': session.unavailable}
        with open(session.options.output + '/metadata/state.toml', 'w') as stateFile:
            stateFile.write(toml.dumps(state))
            stateFile.flush()
    except:
        pass
        
    logging.info('Cleaning up session and closing browser if active')
    logging.getLogger().setLevel(logging.CRITICAL)
    if _signalExit:
        try:
            session.save_screenshot('ancestryAbortImage.png')
        except:
            logging.critical('Failed to save abort screen shot')
            pass
    try:
        session.quit()
    except:
        pass
    logging.getLogger().setLevel(logging.INFO)

def load_tables(queue, path):
    checkpoint = 0
    unavailable = []
    tree_id = tree_name = ''
    hashMap = {}
    logging.info('Checking for hashes to seed image hash cache')
    for dirName in ['apid', 'guid']:
        for fsEntry in os.scandir('{0}/metadata/{1}'.format(path, dirName)):
            if fsEntry.is_file() and '.toml' in fsEntry.name:
                with open(fsEntry.path, 'r') as metaFile:
                    metadata = toml.load(metaFile)
                if 'hash' in metadata and 'image' in metadata:
                    hashMap.update({metadata['hash']: metadata['image']})

    stateFile = '{0}/metadata/state.toml'.format(path)
    if os.path.isfile(stateFile):
        with open(stateFile, 'r') as metaFile:
            metadata = toml.load(metaFile)
        if 'checkpoint' in metadata:
            checkpoint = metadata['checkpoint']
        if 'tree_id' in metadata:
            tree_id = metadata['tree_id']
        if 'tree_name' in metadata:
            tree_name = metadata['tree_name']
        if 'unavailable' in metadata:
            unavailable = metadata['unavailable']
    if hashMap != {}:
        logging.info('Loaded {0} image hashes'.format(len(hashMap)))
    else:
        logging.info('No hashes found to preseed cache')
        
    imageCache = {}
    logging.info('Checking for images to seed image identifier cache')
    for fsObject in os.scandir('{0}/media/dbid'.format(path)):
        if fsObject.is_dir():
            for fsEntry in os.scandir(fsObject.path):
                if fsEntry.is_file():
                    dbid = fsObject.name
                    extension = fsEntry.name.split('.').pop(-1)
                    iid = fsEntry.name.replace('.' + extension, '')
                    imageCache.update({'{0}_{1}'.format(dbid, iid): fsEntry.path})
    if imageCache != []:
        logging.info('Loaded {0} image identifiers'.format(len(imageCache)))
    else:
        logging.info('No images found to preseed cache')

    result = {'checkpoint': checkpoint, 'tree_id': tree_id, 'tree_name': tree_name,
              'unavailable': unavailable, 'hashMap': hashMap, 'imageCache': imageCache}
    queue.put(result)

def load_gedcom(queue, gedcomData):
    people = {}
    person = ''
    families = 0
    apids = []
    guids = []
    apid_total = guid_total = 0
    logging.info('Starting first pass extracting Gedcom data')
    for line in gedcomData.split('\n'):
        if len(line) < 6:
            continue
        tag = line.split(' ')[1]
        if '@P' in tag:
            person = tag
            continue
        if tag == 'NAME' and person != '':
            people.update({person: line[7:]})
            continue
        if '@F' in tag:
            families = families + 1
            continue
        if tag == '_APID':
            apid_total = apid_total + 1
            apid = line.split(' ')[2]
            if apid not in apids:
                apids.append(apid)
            continue
        if tag == 'FILE' and 'http' in line:
            guid_total = guid_total + 1
            url = line.split(' ').pop(2).strip()
            guid = url.split('&').pop(1)[5:]
            if guid not in guids:
                guids.append(guid)
                    
    result = {'people': people,
              'families': families,
              'apid_total': apid_total,
              'apid_unique': len(apids),
              'guid_total': guid_total,
              'guid_unique': len(guids)}
    queue.put(result)

def wait_for_text(session, text, timeout):
    count = 0
    limit = timeout / .2
    while text not in session.page_source:
        if 'this page is temporarily unavailable' in session.page_source:
            return 'unavailable'
        count = count + 1
        time.sleep(.2)
        if count > limit and text not in session.page_source:
            logging.error('Timeout waiting for object visibility')
            return 'timeout'
    return 'ready'
    
def login(session):
    try:
        session.get('{0}/secure/Login'.format(session.options.ancestry))
    except:
        logging.error('Problem loading initial Ancestry.com login page')
        session.save_screenshot('ancestryFailedConnectImage.png')
        exit(1)

    if 'id="signInCustLink"' in session.page_source:
        logging.info('Found sign in screen, clicking link to sign in')
        signIn = session.find_element_by_id('signInCustLink')
        signIn.click()
        session.switch_to.default_content()
        result = wait_for_text(session, 'id="usernameLabel"', 10)
        if result != 'ready':
            logging.error('Login page did not come up after clicking sign in')
            session.save_screenshot('ancestryFailedSignInClick.png')
            exit(1)

    if 'id="signInFrame"' in session.page_source:
        iframe = session.find_element_by_id('signInFrame')
        session.switch_to.frame(iframe)
        
    if 'id="usernameLabel"' in session.page_source:
        logging.info('Attempting login as {0}'.format(session.options.username))
        submitId = 'signInBtn'
        userId = 'username'
        passId = 'password'
        if 'id="usernameHOM"' in session.page_source:
            submitId = 'signinHOM'
            userId = 'usernameHOM'
            passId = 'passwordHOM'
        if submitId not in session.page_source:
            logging.error('Can not find submit button to login')
            session.save_screenshot('ancestryMissingLoginSubmit.png')
            exit(1)
            
        accountField = session.find_element_by_id(userId)
        accountField.clear()
        accountField.send_keys(session.options.username)

        passwordField = session.find_element_by_id(passId)
        passwordField.clear()
        passwordField.send_keys(session.options.password)
    
        submitButton = session.find_element_by_id(submitId)
        submitButton.click()

    session.switch_to.default_content()
    
    count = 0
    loggedIn = False
    while count < 100:
        try:
            if 'About this tree' in session.page_source:
                loggedIn = True
                break
            if 'Products and Services' in session.page_source:
                loggedIn = True
                break
            if 'Invalid credentials' in session.page_source:
                logging.error('Login failed, invalid credentials supplied')
                session.save_screenshot('ancestryFailedLoginImage.png')
                exit(1)
        except:
            pass
        count = count + 1
        time.sleep(.2)

    if not loggedIn:
        logging.error('Login failed, home page did not appear to load')
        session.save_screenshot('ancestryFailedLoginImage.png')
        exit(1)

    soup = BeautifulSoup(session.page_source, features = 'lxml')
    fullName = soup.find(id = 'navAccountUsername').text
    logging.info('Successfully logged in as {0}'.format(fullName))
    session.options.fullName = fullName

def get_image(session, url, targetName, absolute = False):
    headers = {
        "User-Agent":
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    }
    downloadName = '{0}/download.data'.format(os.path.dirname(targetName))
    if os.path.isfile(downloadName):
        logging.debug('Found and removing old {0}'.format(downloadName))
        os.remove(downloadName)

    logging.info('Downloading image at {0}'.format(url))

    downloadSession = requests.session()
    downloadSession.headers.update(headers)
    for cookie in session.get_cookies():
        downloadSession.cookies.update({cookie['name']: cookie['value']})

    try:
        fileData = downloadSession.get(url, allow_redirects=True)
        with open(downloadName, 'wb') as imageFile:
            imageFile.write(fileData.content)
    except:
        logging.error('Error downloading file, retrying')
        time.sleep(1)
        fileData = downloadSession.get(url, allow_redirects=True)
        with open(downloadName, 'wb') as imageFile:
            imageFile.write(fileData.content)        
    fileType = filetype.guess(fileData.content)
    
    hashData = hashlib.sha256()
    hashData.update(fileData.content)
    fileHash = hashData.hexdigest()
    del hashData
    del fileData
    del downloadSession

    if fileHash in session.hashMap:
        if os.path.isfile(session.hashMap[fileHash]):
            if filecmp.cmp(downloadName, session.hashMap[fileHash]):
                logging.info('Downloaded image identical to {0}'.format(session.hashMap[fileHash]))
                os.remove(downloadName)
                return session.hashMap[fileHash], fileHash, True
            else:
                logging.critical('Downloaded image hash identical to {0}'.format(session.hashMap[fileHash]))
                logging.critical('But a binary file compare differs! You should play the lottery!')
                logging.critical('Processing aborted as no clue what to do...')
                exit(1)
        
    loop = 1
    fileName = '{0}.{1}'.format(targetName, fileType.extension)
    while os.path.isfile(fileName):
        logging.debug('Found existing {0}'.format(fileName))
        if filecmp.cmp(downloadName, fileName):
            logging.info('Downloaded image identical to {0}'.format(fileName))
            os.remove(downloadName)
            return fileName, fileHash, True
        fileName = '{0}-{1}.{2}'.format(targetName, loop, fileType.extension)
        loop = loop + 1

    os.replace(downloadName, fileName)
    logging.info('Resulting image named {0}'.format(os.path.basename(fileName)))

    session.hashMap.update({fileHash: fileName})
    return fileName, fileHash, False

def get_screenshot(session, targetName):
    if os.path.isfile(targetName):
        logging.info('Found existing screenshot of source page')
        return targetName
    
    logging.info('Taking screenshot of source page')
    element = session.find_element_by_class_name('article.ancCol.w66')
    element.screenshot(targetName)
    return targetName

def ancestry_media(session, line):
    apid = line.split(' ').pop(2).strip()
    indiv = apid.split(',').pop(0)
    dbid = apid.split(',').pop(1).split(':').pop(0)
    h = apid.split(':').pop(2)
    apidMetaFile = '{0}/metadata/apid/apid_{1}_{2}_{3}.toml'.format(session.options.output, indiv, dbid, h)
    if os.path.isfile(apidMetaFile):
        processData = False
        try:
            with open(apidMetaFile, 'r') as metaFile:
                metadata = toml.load(metaFile)
            if 'image' in metadata:
                if not os.path.isfile(metadata['image']):
                    processData = True
            if session.options.screenshot and metadata['type'] != 'rawimage':
                if 'screenshot' not in metadata:
                    processData = True
                elif not os.path.isfile(metadata['screenshot']):
                    processData = True
        except:
            processData = True
        if not processData:
            if session.line_number > session.checkpoint:
                logging.debug('APID {0} record already processed'.format(apid))
            return 'duplicate'            
        logging.info('APID {0} previously processed but image missing so reprocessing'.format(apid))
        
    if apid in session.unavailable:
        if session.line_number > session.checkpoint:
            logging.debug('APID {0} record duplicate of an unavailable one'.format(apid))
        return 'skip'
    
    logging.info('Processing APID {0}'.format(apid))
    itemStartTime = pendulum.now()

    dbidData = {'dbid': dbid}
    apidData = {'apid': apid,
                'url': 'https://search.ancestry.com/cgi-bin/sse.dll?indiv={0}&dbid={1}&h={2}'.format(indiv, dbid, h)}
    logging.info('Fetching source record page at {0}'.format(apidData['url']))
    session.get(apidData['url'])
    
    sourceType = ''
    if session.current_url != apidData['url']:
        sourceType = 'rawimage'
    else:
        result = wait_for_text(session, 'article ancCol w66', 10)
        if result != 'ready':
            logging.warning('Source page for APID {0} unavailable or timed out'.format(apid))
            if result == 'unavailable':
                session.unavailable = session.unavailable + [apid]
            return result
    if 'id="viewOriginal"' in session.page_source:
        sourceType = 'image'
    if 'Go to website' in session.page_source:
        sourceType = 'url'
    if sourceType == '':
        sourceType = 'text'
    logging.info('Source appears to be a {0} based record'.format(sourceType))
    apidData.update({'type': sourceType})
    
    logging.info('Extracting facts and source information')
    wait_for_text(session, 'personRecordSavedToText', 5)
    soup = BeautifulSoup(session.page_source, features = 'lxml')

    try:
        pageTitle = soup.find(class_ = 'pageTitle').text.strip()
        pageIntro = soup.find(class_ = 'pageIntro').text.strip().replace('\xa0', ' ')
        apidData.update({'title': '{0} {1}'.format(pageTitle, pageIntro)})
        if pageIntro[:7] == 'in the ':
            dbidData.update({'title': pageIntro[7:]})
        else:
            dbidData.update({'title': pageIntro})
    except:
        pass
        
    try:
        personRecord = soup.find(class_ = 'personRecordSavedToText').find('a')
        apidData.update({'person_name': personRecord.text,
                         'person_url': personRecord['href']})
        session.tree_id = personRecord['href'].split('tid=').pop(1)
        treeRecord = soup.find(class_ = 'treeRecordSavedTo')
        session.tree_name = treeRecord.text.strip('"')
    except:
        pass

    try:
        facts = {}
        recordData = soup.find(id = 'recordData')
        for row in recordData.find_all('tr'):
            try:
                th = row.find('th')
                key = th.string.strip(' :\n')
                td = row.find('td')
                value = td.text.replace('\u00a0', ' ').strip(' \n')
                if '#viewNeighbors' in value or '#mapWrapper' in value or 'Search for' in value:
                    continue
                value = value.replace('\n\n', '; ').replace(' ;', ' ').replace('\n', ' ')
                while '  ' in value:
                    value = value.replace('  ', ' ')
                value = value.replace('Name Age; ', '')
                if key.lower() == 'url':
                    value = td.find(class_ = 'link')['href']
                facts.update({key: value})
            except:
                pass
        if facts != {}:
            apidData.update({'facts': facts})
    
        sections = []
        source = soup.find(id = 'sourceCitation')
        for row in source.find_all(class_ = 'citationTitle'):
            sections = sections + [row.text.strip(' ').lower().replace(' ', '_')]
        count = 0
        for row in source.find_all(class_ = 'sourceText'):
            data = row.text.strip(' \n').replace(' Learn more...', '').replace('.\n ', '; ')
            data = data.replace('\u2019', "'").replace('\n', ' ')
            while '  ' in data:
                data = data.replace('  ', ' ')
            if sections[count] == 'description':
                dbidData.update({'description': data})
            elif sections[count] == 'source_citation':
                apidData.update({'citation': data})
            elif sections[count] == 'source_information':
                dbidData.update({'publisher': data.split('Original data:').pop(0).strip(' ;,')})
                if 'Original data:' in data:
                    dbidData.update({'original': data.split('Original data:').pop(1).strip(' ;,')})
            count = count + 1
    except:
        pass
    
    if session.options.screenshot and sourceType != 'rawimage':
        screenshotFile = '{0}/media/apid/apid_{1}_{2}_{3}.png'.format(session.options.output, indiv, dbid, h)
        get_screenshot(session, screenshotFile)
        apidData.update({'screenshot': screenshotFile})

    if sourceType in ['image', 'rawimage']:
        fileName = fileHash = ''
        if sourceType == 'image':
            imageLink = soup.find(class_ = 'photo')['href']
        else:
            imageLink = session.current_url
        imageId = imageLink.split('?').pop(0).split('/').pop(-1)
        uniqueId = dbid + '_' + imageId
        if uniqueId in session.images:
            logging.info('Image already downloaded')
            for fileHash in session.hashMap:
                if imageId in session.hashMap[fileHash]:
                    fileName = session.hashMap[fileHash]
                    break
            if fileName == '':
                fileName = session.images[uniqueId]
                hashData = hashlib.sha256()
                with open(fileName, 'rb') as imageFile:
                    fileData = imageFile.read()
                hashData.update(fileData)
                fileHash = hashData.hexdigest()
                session.hashMap.update({fileHash: fileName})
        else:
            logging.info('Getting image meta data')
            imageDir = '{0}/media/dbid/{1}'.format(session.options.output, dbid)
            if not os.path.isdir(imageDir):
                os.makedirs(imageDir)
            imageFile = '{0}/{1}'.format(imageDir, imageId)

            imageMetaLink = 'http://interactive.ancestry.com/api/v2/Media/GetMediaInfo/{0}/{1}/{2}'.format(dbid, imageId, indiv)
            logging.debug('Image metadata link: {0}'.format(imageMetaLink))
            session.get(imageMetaLink)
            
            result = wait_for_text(session, 'ImageServiceUrlForDownload', 10)
            if result != 'ready':
                logging.error('Page unavailable or timeout loading image metadata')
                return result

            count = 0
            downloadUrl = ''
            while count < 40 and downloadUrl == '':
                soup = BeautifulSoup(session.page_source, features = 'lxml')
                try:
                    imageMetadata = json.loads(soup.find(id = 'json').string)
                    downloadUrl = imageMetadata['ImageServiceUrlForDownload']
                except:
                    count = count + 1
                    time.sleep(.2)
            if downloadUrl == '':
                logging.error('Unable to find image download URL')
                return 'timeout'

            logging.debug('Image download url: {0}'.format(downloadUrl))
            fileName, fileHash, duplicate = get_image(session, downloadUrl, imageFile)
            session.images.update({uniqueId: fileName})
        if fileName != '':
            apidData.update({'image': fileName,
                             'hash': fileHash})
        
    with open(apidMetaFile, 'w') as metaFile:
        metaFile.write(toml.dumps(apidData))
        metaFile.flush()

    dbidMetaFile = '{0}/metadata/dbid/{1}.toml'.format(session.options.output, dbid)
    if not os.path.isfile(dbidMetaFile):
        with open(dbidMetaFile, 'w') as metaFile:
            metaFile.write(toml.dumps(dbidData))
            metaFile.flush()

    itemProcessTime = pendulum.now() - itemStartTime
    logging.info('Item processing time {0} seconds'.format(itemProcessTime.seconds))
    return 'success'

def user_media(session, line):
    url = line.split(' ').pop(2).strip()
    guid = url.split('&').pop(1)[5:]
    guidMetaFile = '{0}/metadata/guid/{1}.toml'.format(session.options.output, guid)
    if os.path.isfile(guidMetaFile):
        processData = False
        try:
            with open(guidMetaFile, 'r') as metaFile:
                metadata = toml.load(metaFile)
            if 'image' in metadata:
                if not os.path.isfile(metadata['image']):
                    processData = True
        except:
            processData = True
        if not processData:
            if session.line_number > session.checkpoint:
                logging.debug('GUID indicates user media item already downloaded')
            return 'duplicate'
        logging.info('GUID previously processed but image missing so reprocessing')
            
    if guid in session.unavailable:
        if session.line_number > session.checkpoint:
            logging.debug('GUID indicates user media item duplicate of unavailable item')
        return 'skip'
    
    itemStartTime = pendulum.now()
    logging.info('Fetching image media page at {0}'.format(url))
    session.get(url)
    
    result = wait_for_text(session, 'showOriginalLink', 10)
    if result != 'ready':
        if result == 'unavailable':
            session.unavailable = session.unavailable + [guid]
        return result
    
    soup = BeautifulSoup(session.page_source, features = 'lxml')
    imageLink = soup.find(id = 'showOriginalLink')['href']

    logging.info('Extracting metadata for the image media')
    editObject = session.find_element_by_id('editObjectLink')
    editObject.click()

    result = wait_for_text(session, 'PictureType', 10)
    if result != 'ready':
        logging.error('Page unavailable or timed out loading')
        return result
    
    soup = BeautifulSoup(session.page_source, features = 'lxml')
    guidData = {'guid': guid,
                'url': url,
                'type': soup.find(id = 'PictureType').find(selected = 'true')['value'],
                'title': soup.find(id = 'MediaName')['value']}
    
    facts = {'description': soup.find(id = 'Description').text,
             'location': soup.find(id = 'Location')['value'],
             'date': soup.find(id = 'Date')['value']}
    if guidData['type'] == 'document':
        facts.update({'transcription': soup.find(id = 'DocumentTranscription').text})
    if guidData['type'] == 'headstone':        
        facts.update({'headstone_name': soup.find(id = 'HeadstoneName')['value'],
                      'headstone_birth_year': soup.find(id = 'Text2')['value'],
                      'headstone_birth_location': soup.find(id = 'Text3')['value'],
                      'headstone_death_year': soup.find(id = 'Text4')['value'],
                      'headstone_death_location': soup.find(id = 'Text5')['value'],
                      'headstone_cemetery_name': soup.find(id = 'HeadstoneCemeteryName')['value']})
    guidData.update({'facts': facts})
                     
    baseName = guidData['title'].lower()
    if baseName in ['', None]:
        baseName = 'untitled'
    for removeCharacter in [',', '-', '"', "'", '&', '.', '(', ')', '[', ']']:
        baseName = baseName.replace(removeCharacter, '')
    baseName = baseName.replace(' ', '_')
    while '__' in baseName:
        baseName = baseName.replace('__', '_')

    imageDir = '{0}/media/{1}'.format(session.options.output, guidData['type'])
    if not os.path.isdir(imageDir):
        os.makedirs(imageDir)
    imageName = '{0}/{1}'.format(imageDir, baseName)

    fileName, fileHash, duplicate = get_image(session, imageLink, imageName)
    guidData.update({'image': fileName,
                     'hash': fileHash})
    
    with open(guidMetaFile, 'w') as metaFile:
        metaFile.write(toml.dumps(guidData))
        metaFile.flush()

    itemProcessTime = pendulum.now() - itemStartTime
    logging.info('Item processing time {0} seconds'.format(itemProcessTime.seconds))
    if duplicate:
        return 'duplicate'
    return 'success'
    
def main():
    global _session
    for signalType in [SIGTERM, SIGABRT]:
        signal(signalType, clean_exit)
    
    parser = OptionParser("usage: %prog [options] accountName password gedcomFile")
    parser.add_option("-c", "--count", dest="count", default="999999",
                      help=SUPPRESS_HELP, metavar="NUMBER")
    parser.add_option("-l", "--logfile", dest="logfile", default="ancestry_extract.log",
                      help="Optional log file location", metavar="FILE")
    parser.add_option("-o", "--output", dest="output", default=".",
                      help="Output directory", metavar="DIR")
    parser.add_option("-r", "--resume",
                      action="store_true", dest="resume", default=False,
                      help="Resume at checkpoint (does not reprocess records)")
    parser.add_option("-s", "--screenshot",
                      action="store_true", dest="screenshot", default=False,
                      help="Generate source record screenshots")
    (options, args) = parser.parse_args()

    if len(args) != 3:
        print('Account name, password, and gedcom file are required arguments')
        exit(1)
    if not os.path.isfile(args[2]):
        print('Gedcom file not found')
        exit(1)
    with open(args[2], "r") as gedcom:
        gedcomData = gedcom.read()
    if '1 SOUR Ancestry.com Family Trees' not in gedcomData or '2 CORP Ancestry.com' not in gedcomData:
        print('Gedcom file does not appear to be from Ancestry.com')
        exit(1)
        
    options.username = args[0]
    options.password = args[1]
    options.gedcom = args[2]

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(name)-8s %(levelname)-8s %(message)s',
                        filename=options.logfile,
                        filemode='a')

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    runStartTime = pendulum.now()
    for checkDir in ['/media/dbid', '/media/apid', '/metadata/guid', '/metadata/apid', '/metadata/dbid']:
        if not os.path.isdir(options.output + checkDir):
            os.makedirs(options.output + checkDir)
    
    gedcomQueue = Queue()
    gedcomProcess = Process(target=load_gedcom, args=(gedcomQueue, gedcomData))
    gedcomProcess.start()
        
    cacheQueue = Queue()
    cacheProcess = Process(target=load_tables, args=(cacheQueue, options.output))
    cacheProcess.start()
    
    logging.info('Launching browser')
    firefoxProfile = FirefoxProfile()
    firefoxProfile.set_preference("browser.startup.homepage", "about:blank")
    firefoxProfile.set_preference("browser.download.folderList", 2)
    firefoxProfile.set_preference("browser.download.panel.shown", False)
    firefoxProfile.set_preference("browser.download.manager.showWhenStarting", False)
    firefoxProfile.set_preference("browser.download.dir", options.output)
    firefoxProfile.set_preference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream")
    firefoxProfile.set_preference("places.history.enabled", False) 
    firefoxOptions = Options()
    firefoxOptions.headless = True
    session = Firefox(options=firefoxOptions, firefox_profile=firefoxProfile)
    atexit.register(session_cleanup, session)
    session.implicitly_wait(15)
    session.fullscreen_window()
    session.options = options
    login(session)

    result = cacheQueue.get()
    session.checkpoint = result['checkpoint']
    session.tree_id = result['tree_id']
    session.tree_name = result['tree_name']
    session.unavailable = []
    if options.resume:
        session.unavailable = result['unavailable']
    session.hashMap = result['hashMap']
    session.images = result['imageCache']
    cacheProcess.join()

    result = gedcomQueue.get()
    people = result['people']
    people_total = len(people)
    family_total = result['families']
    apid_total = result['apid_total']
    apid_unique = result['apid_unique']
    guid_total = result['guid_total']
    guid_unique = result['guid_unique']
    gedcomProcess.join()
    
    logging.info('Found {0} people and {1} families to process'.format(people_total, family_total))
    logging.info('Found {0} unique and {1} total ancestry media items to process'.format(apid_unique, apid_total))
    logging.info('Found {0} unique and {1} total user media items to process'.format(guid_unique, guid_total))

    printFlag = False
    session.line_number = 0
    success = unavailable = duplicate = skip = timeouts = total = count = 0
    person_number = family_number = 0
    apid_number = guid_number = 0
    person = husband = wife = ''
    logging.info('Starting second pass processing Gedcom media items')
    for line in gedcomData.split('\n'):
        session.line_number = session.line_number + 1
        if options.resume:
            if options.resume and session.line_number < session.checkpoint:
                continue
        options.resume = False
        if len(line) < 5:
            continue

        tag = line.split(' ')[1]
        if tag == 'SOUR':
            if session.line_number > session.checkpoint:
                session.checkpoint = session.line_number
            continue
        if '@P' in tag:
            person_number = person_number + 1
            husband = wife = ''
            person = people[tag]
            printFlag = False
            continue
        if '@F' in tag:
            family_number = family_number + 1
            husband = wife = person = ''
            printFlag = False
            continue
        if tag == 'HUSB':
            husband = people[line[7:]]
            continue
        if tag == 'WIFE':
            wife = people[line[7:]]
            continue

        if tag in ['FILE', '_APID']:
            total = total + 1
            if not printFlag:
                if session.line_number > session.checkpoint:
                    if person:
                        logging.info('Processing records for person {0} ({1} of {2})'.format(person, person_number, people_total))
                    else:
                        who = join = ''
                        if husband != '':
                            who = husband
                            join = ' and '
                        if wife != '':
                            who = who + join + wife
                        logging.info('Processing records for family of {0} ({1} of {2})'.format(who, family_number, family_total))
                    printFlag = True

            if ' FILE ' in line and 'f=image&guid=' in line:
                guid_number = guid_number + 1
                logging.debug('User media item {0} of {1} with {2} unique'.format(guid_number, guid_total, guid_unique))
                result = user_media(session, line)
            if ' _APID ' in line:
                apid_number = apid_number + 1
                if '::0' not in line:
                    logging.debug('Ancestry media item {0} of {1} with {2} unique'.format(apid_number, apid_total, apid_unique))
                    result = ancestry_media(session, line)

            if result == 'success':
                count = count + 1
                success = success + 1
            elif result == 'duplicate':
                duplicate = duplicate + 1
            elif result == 'unavailable':
                if person:
                    logging.info('Unavailable item for {0}'.format(person))
                else:
                    logging.info('Unavailable item for {0} / {1}'.format(husband, wife))
                unavailable = unavailable + 1
            elif result == 'timeout':
                timeouts = timeouts + 1
            elif result == 'skip':
                skip = skip + 1

            if count == int(options.count):
                logging.info('Reached limit of {0} records processed'.format(count))
                break

    logging.info('Total overall records:            {0}'.format(total))
    logging.info('Total processed records:          {0}'.format(success))
    logging.info('Total duplicate records:          {0}'.format(duplicate))
    logging.info('Total unavailable records:        {0}'.format(unavailable))
    logging.info('Total skipped due to unavailable: {0}'.format(skip))
    logging.info('Total skipped due to timeouts:    {0}'.format(timeouts))
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info('Starting application shutdown')
        exit(1)
    exit(0)
