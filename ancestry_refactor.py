#!/usr/bin/env python3
##############################################################################
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
##############################################################################

import logging, sys, os, time, json, toml, re, pendulum

from io import StringIO
from multiprocessing import Process, Queue, Lock
from optparse import OptionParser, SUPPRESS_HELP

def clean_date(date):
    months = {'Jan': 'January',   'Feb': 'February', 'Mar': 'March',    'Apr': 'April',    'Mai': 'May',
              'May': 'May',       'Jun': 'June',     'Jul': 'July',     'Aug': 'August',   'Juli': 'July',
              'Sep': 'September', 'Oct': 'October',  'Nov': 'November', 'Dec': 'December', 'Jane': 'January'}
    index = 0
    result = date[:7]
    data = date[7:].title().strip()
    letter = word = False
    while index < len(data):
        if data[index] == '0' and not word:
            index = index + 1
            continue
        if data[index] == ' ':
            word = False
        else:
            word = True
            if data[index].isalpha:
                letter = True
            elif data[index].isdigit and letter == True:
                result = result + ' '
                word = False
        result = result + data[index]
        index = index + 1

    for month in months:
        if ' {0} '.format(month) in result:
            result = result.replace(month, months[month])
    while '  ' in result:
        result = result.replace('  ', ' ')
    return '{0}\n'.format(result)
    
def clean_place(place, places):
    result = place
    result = result.replace('  ', ' ')
    for match in places:
        result = result.replace(match, places[match])
    return result

def build_note(text, level=1, limit=180, strip=True, keyword='NOTE'):
    note = []
    key = int(level)
    tag = keyword
    data = text
    if strip:
        data = data.strip()
    while data != '':
        index = limit
        if len(data) < limit:
            index = len(data)
        else:
            while data[index - 1] == ' ' and index > 0:
                index = index - 1
        chunk = data[:index]
        data = data[index:]
        entry = '{0} {1} {2}'.format(key, tag, chunk)
        note.append(entry)
        tag = 'CONC'
        key = int(level) + 1
    return note

def get_dbid_objects(queue, mediaBase):
    dbidMap = {}
    logging.info('Collecting DBID object information')
    for fileObject in os.scandir(mediaBase + '/metadata/dbid'):
        if not fileObject.is_file():
            continue
        with open(fileObject.path, 'r') as tomlFile:
            metadata = toml.load(tomlFile)
        dbidMap.update({metadata['dbid']: metadata})
    logging.info('DBID object collection completed')
    queue.put(dbidMap)
    return

def get_guid_objects(queue, mediaBase, absolute=False):
    index = 1
    guidMap = {}
    objectMap = {}
    if absolute:
        imageBase = '{0}'.format(mediaBase) + '/media/{0}/{1}'
    else:
        imageBase = './media/{0}/{1}'
    logging.info('Collecting GUID object information')
    for fileObject in os.scandir(mediaBase + '/metadata/guid'):
        if not fileObject.is_file():
            continue
        with open(fileObject.path, 'r') as tomlFile:
            metadata = toml.load(tomlFile)
        baseName = os.path.basename(metadata['image'])
        imageName = imageBase.format(metadata['type'], baseName)
        imageExtension = imageName.split('.').pop(-1)
        
        pictureName = metadata['title']
        if pictureName == '':
            pictureName = 'Untitled'
            
        objectId = '@M{0}@'.format(index)
        objectEntry = ['0 {0} OBJE'.format(objectId),
                       '1 FILE {0}'.format(imageName),
                       '1 FORM {0}'.format(imageExtension),
                       '1 TITL {0}'.format(pictureName)]
        
        if metadata['type'] == 'portrait':
            objectEntry.append('1 TYPE photo')
        else:
            objectEntry.append('1 TYPE {0}'.format(metadata['type']))
            
        if 'url' in metadata and metadata['url'] != '':
            objectEntry.append('1 NOTE {0}'.format(metadata['url']))

        if 'facts' in metadata:
            facts = metadata['facts']
            for key in ['description', 'transcription']:
                if key in facts and facts[key] != '':
                    note = build_note(facts[key], 1)
                    if len(note) > 0:
                        for item in note:
                            objectEntry.append(item)
                    
        objectMap.update({objectId: objectEntry})
        guidMap.update({metadata['guid']: objectId})
        index = index + 1
        if index > 99999:
            logging.error('100000 GUID objects not supported, APID range starts there')
            exit(1)
    logging.info('GUID object collection completed')
    queue.put((guidMap, objectMap))
    return

def read_apids(localQueue, localLock, remoteQueue, remoteLock):
    while True:
        localLock.acquire()
        if not localQueue.empty():
            fileData = localQueue.get()
            localLock.release()
        else:
            localLock.release()
            time.sleep(.01)
            continue
        if 'exit' in fileData and fileData['exit']:
            break
        with open(fileData['fileName'], 'r') as tomlFile:
            tomlData = toml.load(tomlFile)
        remoteLock.acquire()
        remoteQueue.put(tomlData)
        remoteLock.release()
    return

def get_apid_objects(queue, mediaBase, absolute=False):
    workLock = Lock()
    workQueue = Queue()
    
    readers = os.cpu_count()
    readLock = Lock()
    readQueue = Queue()
    readProcesses = []
    for number in range(readers):
        readProcess = Process(target = read_apids,
                              args = (readQueue, readLock, workQueue, workLock))
        readProcess.start()
        readProcesses.append(readProcess)
        
    logging.info('Collecting APID object information')
    fileList = []
    fileTotal = 0
    for fileObject in os.scandir(mediaBase + '/metadata/apid'):
        if not fileObject.is_file():
            continue
        fileList.append({'fileName': fileObject.path})
        fileTotal = fileTotal + 1
        
    readLock.acquire()
    for item in fileList:
        readQueue.put(item)
    for item in readProcesses:
        readQueue.put({'exit': True})
    readLock.release()

    index = 100000
    apidImageMap = {}
    apidScreenshotMap = {}
    apidFullMap = {}
    objectMap = {}
    imageCache = {}
    itemCount = 0
    if absolute:
        imageBase = '{0}'.format(mediaBase) + '/media/{0}'
    else:
        imageBase = './media/{0}'
    while True:
        workLock.acquire()
        if not workQueue.empty():
            metadata = workQueue.get()
            workLock.release()
        else:
            workLock.release()
            time.sleep(.01)
            continue

        itemCount = itemCount + 1
        apidFullMap.update({metadata['apid']: metadata})
        if 'image' in metadata:
            if metadata['image'] not in imageCache:
                baseName = metadata['image'].split('/media/').pop(1)
                imageName = imageBase.format(baseName)
                imageExtension = imageName.split('.').pop(-1)

                objectId = '@M{0}@'.format(index)
                objectEntry = ['0 {0} OBJE'.format(objectId),
                               '1 FILE {0}'.format(imageName),
                               '1 FORM {0}'.format(imageExtension),
                               '1 TYPE document']

                objectMap.update({objectId: objectEntry})
                imageCache.update({metadata['image']: objectId})
                index = index + 1
            else:
                objectId = imageCache[metadata['image']]
            apidImageMap.update({metadata['apid']: objectId})
        if 'screenshot' in metadata:
            baseName = os.path.basename(metadata['screenshot'])
            imageName = imageBase.format('apid') + '/' + baseName
            imageExtension = imageName.split('.').pop(-1)
                                       
            if 'title' in metadata and metadata['title'] != '':
                title = metadata['title']
            else:
                title = 'Ancestry.com Source Record, {0}'.format(metadata['apid'])
                                       
            objectId = '@M{0}@'.format(index)
            objectEntry = ['0 {0} OBJE'.format(objectId),
                           '1 FILE {0}'.format(imageName),
                           '1 FORM {0}'.format(imageExtension),
                           '1 TITL {0}'.format(title),
                           '1 REFN {0}'.format(metadata['apid'])]
            
            if 'url' in metadata and metadata['url'] != '':
                objectEntry.append('1 NOTE {0}'.format(metadata['url']))
                
            objectMap.update({objectId: objectEntry})
            index = index + 1
            apidScreenshotMap.update({metadata['apid']: objectId})

            if itemCount == fileTotal:
                break

    for readProcess in readProcesses:
        readProcess.join()
    queue.put((apidImageMap, apidScreenshotMap, apidFullMap, objectMap))    
    logging.info('APID object collection completed')

def get_people_urls(gedcomData, apidFullMap):
    people = {}
    found = False
    logging.info('Extracting person specific URL information')
    for line in gedcomData.split('\n'):
        if len(line) > 5:
            tag = line.split(' ')[1]
            if '@P' in tag:
                person = tag
                found = False
                continue
            if tag == '_APID' and not found:
                apid = line.split(' ')[2]
                if apid in apidFullMap:
                    if 'person_url' in apidFullMap[apid] and apidFullMap[apid]['person_url'] != '':
                        people.update({person: apidFullMap[apid]['person_url']})
                        found = True
    logging.info('Person URL extraction completed')
    return people

def get_sources(queue, options, gedcomData, dbidMap, apidImageMap):
    sources = {}
    dbidList = []
    sourceList = []
    logging.info('Generating updated source records')
    gedcom = StringIO(gedcomData)
    line = gedcom.readline()
    while line:
        if '0 @S' not in line:
            if ' _APID ' in line:
                dbid = line.split(',')[1].split(':')[0]
                if dbid not in dbidList:
                    dbidList.append(dbid)
            if ' SOUR ' in line:
                source = line.split(' ')[2].strip()
                if source not in sourceList:
                    sourceList.append(source)
            line = gedcom.readline()
            continue
        apid = ''
        source = []
        sourceData = [line]
        sourceId = line.split(' ')[1]
        if sourceId not in sourceList:
            logging.error('Found unreferenced source record {0}'.format(sourceId))
            line = gedcom.readline()
            continue
        line = gedcom.readline().strip()
        while line[0] != '0':
            sourceData.append(line)
            if '_APID' in line:
                apid = line.strip().split(' ')[2]
                dbid = apid.split(':').pop(0).split(',').pop(1)
                if dbid not in dbidList:
                    logging.error('Found unreferenced DBID record {0} in source record {1}'.format(dbid, sourceId))
                    line = gedcom.readline()
                    continue                    
            line = gedcom.readline().strip()
        if apid == '':
            sources.update({sourceId: sourceData})
            continue
        original = []
        publisher = []
        description = []
        if dbid in dbidMap:
            if 'publisher' in dbidMap[dbid] and dbidMap[dbid]['publisher'] != '':
                publisher = build_note(dbidMap[dbid]['publisher'], keyword='PUBL')
            if 'original' in dbidMap[dbid] and dbidMap[dbid]['original'] != '':
                original = build_note('Original Data: {0}'.format(dbidMap[dbid]['original']), keyword='NOTE')
            if 'description' in dbidMap[dbid] and dbidMap[dbid]['description'] not in ['', 'Learn more...']:
                description = build_note(dbidMap[dbid]['description'], keyword='NOTE')
        else:
            logging.error('Found DBID record {0} with no data'.format(dbid))            
        inTitle = False
        inPublisher = False
        shortTitle = ''
        for entry in sourceData:
            if ' _APID ' in entry:
                if options.keep_apid:
                    source.append(entry)                    
                continue
            if inTitle:
                if ' CONC ' in entry or ' CONT ' in entry:
                    source.append(entry)
                    continue
                inTitle = False
                if shortTitle != '':
                    source.append('1 ABBR {0}'.format(shortTitle))
            if inPublisher:
                if ' CONC ' in entry or ' CONT ' in entry:
                    source.append(entry)
                    continue
                inPublisher = False
                if options.source_url:
                    source.append('1 NOTE https://search.ancestry.com/search/db.aspx?dbid={0}'.format(dbid))
            if 'NOTE' in entry and len(entry) < 8:
                continue
            if 'CONC' in entry and len(entry) < 8:
                continue
            if ' PUBL ' in entry:
                if publisher != []:
                    for item in publisher:
                        source.append(item)
                else:
                    source.append(entry)
                inPublisher = True
                continue
            if ' TITL ' in entry:
                if len(entry[7:].strip()) <= 60:
                    shortTitle = entry[7:].strip()
                if dbid in dbidMap:
                    if entry[7:].strip() != dbidMap[dbid]['title']:
                        logging.error('Gedcom Title: {0}'.format(entry[7:].strip()))
                        logging.error('DBID Title  : {0}'.format(dbidMap[dbid]['title']))
                inTitle = True
            source.append(entry)
        if original != []:
            for item in original:
                source.append(item)
        if description != []:
            for item in description:
                source.append(item)
        search = apid.split(':').pop(0) + '::'
        for entry in apidImageMap:
            if search in entry:
                source.append('1 OBJE {0}'.format(apidImageMap[entry]))
        sources.update({sourceId: source})
    logging.info('Updated source records generated')
    queue.put(sources)
    
def emit_line(handle, data):
    if len(data) > 254:
        if ' PAGE ' in data:
            data = data.replace('Record Group Title', 'Record Group')
            data = data.replace('Series Title', 'Series')
            data = data.replace('Washington, D.C.; Washington, D.C.;', 'Washington, D.C.;')
        if len(data) > 254:
            logging.error('Truncating invalid line length: {0}'.format(data))
            data = '{0}\n'.format(data[:254])
    handle.write(data)
    
def main():
    parser = OptionParser("usage: %prog [options] inGedcomFile rootMediaDir <outGedcomFile>")
    parser.add_option("-a", "--absolute",
                      action="store_true", dest="absolute", default=False,
                      help="Generate absolute file path references")
    parser.add_option("-B", "--build-citation-page",
                      action="store_true", dest="citation_page", default=False,
                      help="If missing attempt to build citation page from extracted facts")
    parser.add_option("-C", "--citation-url",
                      action="store_true", dest="citation_url", default=False,
                      help="Include Ancestry.com source citation URL")
    parser.add_option("-d", "--clean-dates",
                      action="store_true", dest="clean_dates", default=False,
                      help="Perform simple date cleanups")
    parser.add_option("-D", "--source-description",
                      action="store_true", dest="source_description", default=False,
                      help="Include source descriptions when known")
    parser.add_option("-F", "--citation-facts",
                      action="store_true", dest="citation_facts", default=False,
                      help="Include extracted source citation facts when known")
    parser.add_option("-I", "--include-screenshot-media",
                      action="store_true", dest="screenshots", default=False,
                      help="Include media for source citation screenshots")
    parser.add_option("-K", "--keep-apid-tags",
                      action="store_true", dest="keep_apid", default=False,
                      help="Keep all _APID tags, filtered out by default")
    parser.add_option("-l", "--logfile", dest="logfile", default="ancestry_refactor.log",
                      help="Optional log file location", metavar="FILE")
    parser.add_option("-o", "--overwrite",
                      action="store_true", dest="overwrite", default=False,
                      help="Over write output file if it exists")
    parser.add_option("-p", "--clean-places", dest="clean_places", default=None,
                      help="Perform simple place cleanups using mapping file", metavar="FILE")
    parser.add_option("-P", "--person-url",
                      action="store_true", dest="person_url", default=False,
                      help="Include Ancestry.com person URL when known")
    parser.add_option("-S", "--source-url",
                      action="store_true", dest="source_url", default=False,
                      help="Include Ancestry.com source URL when known")
    (options, args) = parser.parse_args()

    if len(args) < 2:
        print('Gedcom file and root of media directory tree are required arguments')
        exit(1)
    if not os.path.isfile(args[0]):
        print('Gedcom file {0} not found'.format(args[0]))
        exit(1)
    if not os.path.isdir(args[1]):
        print('Base media directory {0} not found'.format(args[1]))
        exit(1)
    if options.clean_places != None:
        if not os.path.isfile(options.clean_places):
            print('Places file {0} not found'.format(options.clean_places))
            exit(1)
        
    gedcomFile = args[0]
    mediaBase = args[1]
    if len(args) > 2 and args[2] != '':
        newGedcomFile = args[2]
    else:
        newGedcomFile = '{0}/{1}'.format(mediaBase, os.path.basename(gedcomFile))
    if not options.overwrite:
        if os.path.isfile(newGedcomFile):
            print('New Gedcom file {0} already exists and over write not specified'.format(newGedcomFile))
            exit(1)
        
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(name)-8s %(levelname)-8s %(message)s',
                        filename=options.logfile,
                        filemode='w')

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    runStartTime = pendulum.now()
    with open(gedcomFile, 'r') as gedcom:
        gedcomData = gedcom.read()

    dbidQueue = Queue()
    dbidProcess = Process(target = get_dbid_objects,
                          args = (dbidQueue, mediaBase))
    dbidProcess.start()
        
    apidQueue = Queue()
    apidProcess = Process(target = get_apid_objects,
                          args = (apidQueue, mediaBase))
    apidProcess.start()

    guidQueue = Queue()
    guidProcess = Process(target = get_guid_objects,
                          args = (guidQueue, mediaBase))
    guidProcess.start()
    guidMap, guidObjects = guidQueue.get()
    guidProcess.join()

    if options.clean_places != None:
        try:
            with open(options.clean_places, 'r') as placeFile:
                places = toml.load(placeFile)
        except:
            logging.error('Error parsing places file {0}, may not be valid TOML syntax'.format(options.clean_places))
            exit(1)

    dbidMap = dbidQueue.get()
    dbidProcess.join()
    
    apidImageMap, apidScreenshotMap, apidFullMap, apidObjects = apidQueue.get()
    apidProcess.join()

    sourceQueue = Queue()
    sourceProcess = Process(target = get_sources,
                            args = (sourceQueue, options, gedcomData, dbidMap, apidImageMap))
    sourceProcess.start()
    
    people = get_people_urls(gedcomData, apidFullMap)

    sources = sourceQueue.get()
    sourceProcess.join()
    
    gedcom = open(newGedcomFile, 'w')

    lineNumber = contextLevel = 0
    entity = entityId = mediaItem = pageText = sourceCitation = certificateNumber = apid = ''
    inMedia = inSource = inCitation = foundPage = False
    media = []
    citation = []
    logging.info('Refactoring Gedcom data')
    for line in gedcomData.split('\n'):
        lineNumber = lineNumber + 1
        if (len(line)) < 5:
            continue
        parts = line.split(' ')
        currentLevel = parts[0]
        tag = parts[1]
        line = line + '\n'

        if inSource and currentLevel <= contextLevel:
            if entityId in sources:
                for item in sources[entityId]:
                    if '0 @S' not in item:
                        emit_line(gedcom, '{0}\n'.format(item))
            inSource = False
                
        if inMedia and currentLevel <= contextLevel:
            if mediaItem != '':
                emit_line(gedcom, '{0}\n'.format(mediaItem))
            else:
                for item in media:
                    emit_line(gedcom, item)
            inMedia = False
            mediaItem = ''
            media = []

        if inCitation and currentLevel <= contextLevel:
            if foundPage:
                emit_line(gedcom, pageText) 
            elif options.citation_page:
                if certificateNumber != '':
                    if coreEventDate != '' or coreEventPlace != '':
                        pageText = '{0} PAGE '.format(int(contextLevel) + 1)
                        if coreEventPlace != '':
                            pageText = '{0}{1}; '.format(pageText, coreEventPlace)
                        if coreEventDate != '':
                            pageText = '{0}{1}; '.format(pageText, coreEventDate)
                        pageText = '{0}Certificate: {1}\n'.format(pageText, certificateNumber)
                        emit_line(gedcom, pageText)
                    elif sourceCitation != '':
                        if certificateNumber not in sourceCitation:
                            sourceCitation = '{0}, Certificate: {1}\n'.format(sourceCitation.strip(), certificateNumber)
                        emit_line(gedcom, '{0} PAGE {1}\n'.format(int(contextLevel) + 1, sourceCitation))
                elif licenseNumber != '':
                    if coreEventDate != '' or coreEventPlace != '':
                        pageText = '{0} PAGE '.format(int(contextLevel) + 1)
                        if coreEventPlace != '':
                            pageText = '{0}{1}; '.format(pageText, coreEventPlace)
                        if coreEventDate != '':
                            pageText = '{0}{1}; '.format(pageText, coreEventDate)
                        pageText = '{0}License: {1}\n'.format(pageText, licenseNumber)
                        emit_line(gedcom, pageText)
                    elif sourceCitation != '':
                        if licenseNumber not in sourceCitation:
                            sourceCitation = '{0}, License: {1}\n'.format(sourceCitation.strip(), licenseNumber)
                        emit_line(gedcom, '{0} PAGE {1}\n'.format(int(contextLevel) + 1, sourceCitation))
                elif sourceCitation != '':
                    emit_line(gedcom, '{0} PAGE {1}\n'.format(int(contextLevel) + 1, sourceCitation))
                    
            for item in citation:
                emit_line(gedcom, item)
            inCitation = False
        
        if tag == 'HEAD':
            entity = tag
        elif '@' in tag:
            emit_line(gedcom, line)
            entity = parts[2]
            entityId = tag
            if entity == 'SOUR':
                inSource = True
                contextLevel = currentLevel
            if options.person_url and entity == 'INDI':
                if entityId in people:
                    emit_line(gedcom, '{0} NOTE {1}\n'.format(int(currentLevel) + 1, people[entityId]))
            continue
        elif tag == 'PLAC':
            if options.clean_places != None:
                line = clean_place(line, places)
        elif tag == 'DATE':
            if options.clean_dates:
                line = clean_date(line)
        elif tag == 'OBJE':
            if '@' not in line:
                inMedia = True
                contextLevel = currentLevel
        elif tag == 'SOUR':
            inCitation = True
            foundPage = False
            contextLevel = currentLevel
            citation = []
            pageText = sourceCitation = certificateNumber = licenseNumber = collection = apid = ''
            coreEventType = coreEventDate = coreEventPlace = ''
            emit_line(gedcom, line)
            continue
        elif tag in ['BIRT', 'BAPT', 'CHR', 'MARR', 'BURI', 'CREM', 'NATU', 'PROB', 'WILL',
                     'GRAD', 'RETI', 'EVEN', 'RESI']:
            if len(line.strip()) > (len(tag) + 3):
                offset = len(tag) + 3
                emit_line(gedcom, '{0}\n'.format(line[:offset]))
                emit_line(gedcom, '{0} NOTE {1}'.format(int(currentLevel) + 1, line[offset:]))
                continue
            
        if inMedia:
            if tag == 'FILE':
                if 'http' in line and 'guid=' in line:
                    guid = line.split('&').pop(1).split('=').pop(1)
                    if guid in guidMap:
                        mediaItem = '{0} OBJE {1}'.format(contextLevel, guidMap[guid])
            media.append(line)
            continue

        if inCitation:
            if tag == '_APID':
                if options.keep_apid:
                    citation.append(line)
                apid = parts[2]
                dbid = apid.split(',')[1].split(':')[0]
                if apid in apidFullMap:
                    apidData = apidFullMap[apid]
                    if 'citation' in apidData:
                        sourceCitation = apidData['citation']
                    if dbid in dbidMap and 'title' in dbidMap[dbid]:
                        collection = dbidMap[dbid]['title']
                        for key in ['Birth', 'Death', 'Marriage', 'Divorce']:
                            if key in collection:
                                coreEventType = key
                                break
                    if 'facts' in apidData and len(apidData['facts']) > 0:
                        facts = apidData['facts']
                        citation.append('{0} DATA\n'.format(currentLevel))
                        first = True
                        coreDates = []
                        corePlaces = []
                        if coreEventType != '':
                            coreDates = ['{0} Date'.format(coreEventType)]
                            corePlaces = ['{0} Place'.format(coreEventType)]
                            if coreEventType == 'Divorce':
                                coreDates.append('Decree Date')
                                corePlaces.append('County of Decree')
                            if coreEventType == 'Marriage':
                                coreDates.append('Marriage License Date')
                                corePlaces.append('Marriage License Place')
                        for fact in facts:
                            factData = facts[fact]
                            if options.clean_dates and 'Date' in fact:
                                factData = clean_date(factData).strip()
                            if options.citation_facts:
                                if first:
                                    first = False
                                    note = build_note('{0}: {1}'.format(fact, factData),
                                                      level = int(currentLevel) + 1, keyword='TEXT')
                                else:
                                    note = build_note('{0}: {1}'.format(fact, factData),
                                                      level = int(currentLevel) + 2, keyword='CONT')
                                for item in note:
                                    citation.append('{0}\n'.format(item))
                            if 'Certificate' in fact:
                                certificateNumber = factData
                                if pageText != '' and certificateNumber not in pageText:
                                    pageText = '{0}, Certificate: {1}\n'.format(pageText.strip(), certificateNumber)
                            if 'License' in fact:
                                licenseNumber = factData
                                if pageText != '' and licenseNumber not in pageText:
                                    pageText = '{0}, License: {1}\n'.format(pageText.strip(), licenseNumber)
                            for checkText in coreDates:
                                if checkText in fact:
                                    coreEventDate = '{0}: {1}'.format(fact, factData)
                                    break
                            for checkText in corePlaces:
                                if checkText in fact:
                                    coreEventPlace = '{0}: {1}'.format(fact, factData)
                                    break
                    if options.citation_url and 'url' in apidData:
                        citation.append('{0} NOTE {1}\n'.format(currentLevel, apidData['url']))
                elif options.citation_url:
                    indiv = apid.split(',').pop(0)
                    h = apid.split(':').pop(2)
                    url = 'https://search.ancestry.com/cgi-bin/sse.dll?indiv={0}&dbid={1}&h={2}'.format(indiv, dbid, h)
                    citation.append('{0} NOTE {1}\n'.format(currentLevel, url))
                if apid in apidImageMap:
                    citation.append('{0} OBJE {1}\n'.format(currentLevel, apidImageMap[apid]))
                if options.screenshots and apid in apidScreenshotMap:
                    citation.append('{0} OBJE {1}\n'.format(currentLevel, apidScreenshotMap[apid]))
                if dbid in dbidMap and 'title' in dbidMap[dbid]:
                    collection = dbidMap[dbid]['title']
                continue
            if tag == 'PAGE':
                pageText = line
                foundPage = True
                continue
            citation.append(line)
            continue
            
        if tag == 'TRLR':
            for object in guidObjects:
                for item in guidObjects[object]:
                    emit_line(gedcom, '{0}\n'.format(item))
            for object in apidObjects:
                first = ''
                if options.screenshots:
                    first = None
                for item in apidObjects[object]:
                    if first == None:
                        emit_line(gedcom, '{0}\n'.format(item))
                        continue
                    if first == '':
                        first == item
                        continue
                    if 'FILE' in item and 'apid_' in item and 'png' in item:
                        break
                    emit_line(gedcom, '{0}\n'.format(first))
                    emit_line(gedcom, '{0}\n'.format(item))
                    first = None
                    
        if not inSource:
            emit_line(gedcom, line)
    gedcom.flush()
    gedcom.close()
    logging.info('Gedcom refactoring completed')
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info('Starting application shutdown')
        exit(1)
    exit(0)
