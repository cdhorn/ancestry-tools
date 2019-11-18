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

import os, sys

if len(sys.argv) < 2:
    print('Error: No filename provided')
    exit(1)
    
fileName = sys.argv[1]
if not os.path.isfile(fileName):
    print('Error: File {0} not found'.format(fileName))
    exit(1)
    
with open(fileName, 'r') as fileHandle:
    data = fileHandle.read()

for line in data.split('\n'):
    if len(line) < 5:
        continue
    if ' CONT' in line or ' CONC' in line:
        indent = (int(line[0])-1)*5*' '
    else:
        indent = int(line[0])*5*' '
    line = '{0}{1}{2}'.format(line[0], indent, line[1:])
    print(line)
