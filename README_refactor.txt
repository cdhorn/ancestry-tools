
The ancestry_refactor.py tool is a next step utility designed to take the Gedcom
file used for the download and refactor it to clean things up and enhance it so
that it can be imported into another genealogy program. In this case I use Gramps
but it should work fine with others as well.

The following is a list of the things that are or can be done depending on the
various command line options provided:

1. Replace all of the _APID references in the source citations with proper links
to the downloaded media images if the record had an associated image. This can be
done using a relative or absolute path reference to the image. (See -a flag) 

2. Add the links to the optional screenshots of the source citation record pages
to the source citation records. (See -I flag)

3. Add missing or enhance the existing source citations. In some cases the source
citation page shows the citation information but it may be missing in the Gedcom.
In other cases if a birth, marriage, death or divorce fact is identifiable and a
certificate or license number is provided and not part of the source citation it
is appended. If a certificate or license number is provided and no citation exists
at all one is generated using the information. (See -B flag)

4. Add all of the extracted facts related to the source citation to the citation
notes so they are available for reference when imported else where. As with other
things Ancestry does not include any of this information in their Gedcom export
process. (See -F flag)

5. Save the URL to the source citation page in the source citation notes. (See
-C flag)

6. Remove stray source records that are not used or referenced by any of the source
citations. I found several of these in my tree and do not understand why they were
there.

7. Add better publisher information to all the source records. Nearly every record
from Ancestry.com has the publisher set to a vanilla "Ancestry.com Operations, Inc."
But we have the extracted source information about the publisher, so we replace the
generic boiler plate with that. An example being "Ancestry.com. London, England, 
Church of England Deaths and Burials, 1813-2003 [database on-line]. Provo, UT, USA: 
Ancestry.com Operations, Inc., 2010"

8. If found in the extract add information about the original data source that the
database was created from as a source note.

9. If found, and almost every collection has it, save the source description for
the database as a source note. Note sometimes the original data and the source
description overlap but most of the time they do not.

10. Save the URL to the main database search page for the source as a source note.
(See -S flag)

11. During the source citation extraction process an attempt is made to identify
the URL to the person page in the tree. If the information is available the URL
can be saved in the person notes. (See -P flag)

12. If requested use an external places file to perform some simple place name
substitutions. For example I prefer to use "United States" and not USA or U.S.A or
United States of America but I standardized on that some years after starting my
tree. Note these substitutions are only applied to place names identified by the
PLAC tag. Place names that occur in facts or notes are not touched. (See -p flag)

13. If requested try to cleanup the date format a little. In general this will try
to remove leading 0's in numbers, add a space after the month but before the year
if there was a typo, and expand three letter month abbreviations into full month
names. This applies to any dates identified by the DATE tag but also to any of
the extracted facts added to a source citation note if the word "Date" is found
in the fact description. (See -d flag)

14. Proper @Mxxxxx@ media records are generated for every media item in the
Gedcom and appended to the end of the Gedcom before the closing TRLR tag. All
of the OBJE/FILE/FORM sequences in the Gedcom for the user media are replaced
with the proper OBJE @Mxxxx@ pointer record and of course the pointer records
are used for all the source citation links to images or screenshots. A sample
entry of a proper media record looks as follows:

0 @M1620@ OBJE
1 FILE ./media/portrait/margaretha_fuchs_nee_pfeifer.jpg
1 FORM jpg
1 TITL Margaretha Fuchs nee Pfeifer
1 TYPE photo
1 NOTE http://trees.ancestry.com/rd?f=image&guid=5f2b1da5-9ef1-4dd3-b9c8-1a1e4e8010e6&tid=81556269&pid=10836
1 NOTE Margaretha Fuchs nee Pfeifer. Cabinet card in a Fuchs Family Album, one of the few that were labelled.

Note the URL to the media page is kept as a media note along with the description
if one was provided. The media type is added although I am unsure if any import
programs support it.

15. Media images associated with the source citation records can also be linked
to the actual source record. For common sources like censuses the source record
can end up with dozens or hundreds of these.

16. Many other programs may not recognize the _APID tags, so these are stripped
out by default. This can be overridden. (See -K flag)

A sample invocation of the utility might be as follows:

./ancestry_refactor.py -BCdDFPSo -p ./places.toml ancestry_gedcom.ged ./familytree ./familytree/refactored_gedcom.ged

This applies pretty much all the options to the downloaded ancestry_gedcom.ged using
the extracted tree information under familytree and creates the new file in the
familytree directory. This is convenient if you want to tar or zip everything up.


To provide some frame of reference, at the time I wrote this my tree contained
12,383 people, 1,628 user media items, and 34,472 unique source citation records.

The downloaded Gedcom from Ancestry.com was 17 MB in size, the refactored one
using all the options was 79 MB in size.

The original Gedcom import into the Gramps program resulted in 10,232 note
records and 8,527 of those were notes related to import problems.  The import
of the refactored tree resulted in 229,243 notes and only 117 of those were
related to import problems.
