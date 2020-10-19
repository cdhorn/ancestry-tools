
The ancestry_extract.py utility is designed to take a Gedcom from Ancestry.com as
input along with other optional parameters. It then uses the Selenium webdriver
to open a Firefox browser to login and navigate the site, pulling up the numerous
media and source records, extracting any relevant fact data, generating a screenshot
of the source record page, and then downloading the image if one is available.

The original approach was to use the browser to save the images and then pull them
out of the download directory, but after embarking on the project I ran into the
utility by neRok00 that also downloaded the APID images by querying the Ancestry
media API to get the download link. So I use the same approach here, passing the
cookie from the Selenium session to the requests module, fetching the image data
with that, and then passing it back to the Selenium session. When this breaks in 
the future I may switch back to the original technique.

The downloaded images and information are stored in a standard directory structure
underneath the base directory specified. For example, if you set the base directory
to familytree the resulting heirarchy will be as follows:

familytree
|
|--------- logs
|
|--------- media
|          |---- apid
|          |---- dbid
|          |     |---- 1708 
|          |     |---- 1787
|          |     
|          |---- document
|          |---- headstone
|          |---- other
|          |---- portrait
|
|--------- metadata
           |------- apid
	   |------- dbid
	   |------- guid

The Gedcom downloaded from Ancestry.com will use an _APID tag in all the source
citations to identify the location in the original source record. The APID, which
likely is short hand for Ancestry Page Identifier, has three parts the middle
of which is the database identifier. The APID can be used to construct a URL to
pull up the source citation page or the main search page for the given database.

In the directory structure above the screenshots of the Ancestry.com source citation
pages are saved in the media/apid subdirectory. If there is an actual image available
that is saved in the specific media/dbid subdirectory. Extracted information that
is related to the citation, like the facts and information about the screenshots and
image files, are saved in the metadata/apid subdirectory. And extracted information
related to the source itself, like the publisher, original source and the source
description are saved in the metadata/dbid directory.

The Gedcom will also contain numerous user media items as well. These are all
identified with the OBJE/FILE/FORM tag sequence. The FILE tag will contain a URL
that links to the user media item page. The link contains a few parts but the
GUID can be used to uniquely identify an instance of an item. If the same item
is linked to multiple people the links will all have the GUID in common. If the
image was linked to different people at different times, say from an Ancestry
hint from one person, then later a hint from another, each "instance" will have
a different GUID even though it is the same image. The code tries to detect these
situations to only keep a single copy of any given image on disk, and will update
the saved metadata so it all points to the same file.

In the directory structure above the actual media images are saved in subdirectories
under media based on the tagged media type. The three common ones are portrait for
photos, document, and headstone. Note many users often upload or link to items and
do not tag them properly, so things may not always end up where expected. Instead
of using the GUID for the file names, the names used are generated based on the
picture names by pushing them to lowercase, stripping out most non-alphanumeric
characters and then replacing spaces with underscores. This makes them easier to
identify. Any corresponding information about the image, including any extracted
facts like transcriptions or headstone information, are saved in the metadata/guid
subdirectory.

Note all metadata is stored in the TOML format, with a single file per object. TOML
was choosen as it is generally easier for humans to edit than other common structured
formats and it is faster to parse than YAML.

A sample invocation of the program might be as follows:

./ancestry_extract.py -o ./familytree -a username@domain -p password -g ancestry_gedcom.ged

This will create the familytree structure described earlier and generate screenshots
of all the source citation pages.

The program now has support for a configuration file. If run with no arguments it will
check for ancestry_extract.toml and read in the parameters from there. It can optionally
be passed the name of the configuration file as well.  The sample one includes comments
to describe the options.
    
The download process is single threaded, one page and image at a time.  For a large tree
it can take a very long time to run. If interrupted it should try to shutdown gracefully.
It is designed so you can restart it, and it should work through things and pretty
much pick up where it left off.

If you some weeks or months later download an updated Gedcom you should be able to
process it the same as the first one and it should parse through and only download
and screenshot new items.

Note sometimes items in the tree come up as "unavailable". I have a handful of
these in my tree, all associated with a couple databases related to the Netherlands.
I have not investigated in depth but suspect maybe the collection was reindexed
or something else done on Ancestry's side that broke things.
