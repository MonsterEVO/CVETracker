import urllib
import gzip
import os
from xml.dom import minidom
import psycopg2 as dbapi2



#varibles
path = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz"
gzfile = "cvelsit.xml.gz"
xmlfile = "cvelist.xml"


#Grab file to be used for nist website
cvefile = urllib.URLopener()
cvefile.retrieve(path, gzfile)

#uncompress file
inF = gzip.GzipFile(gzfile, 'rb')
s = inF.read()
inF.close()

#save uncompressed file
outF = file (xmlfile, 'wb')
outF.write(s)
outF.close()

#remove compressed file
os.remove(gzfile)

#open connection with database
conn = dbapi2.connect (database="CVE", host="localhost", user="postgres", password="postgres")

#Establish a cursor
cur = conn.cursor()

#parse data
xmldoc = minidom.parse("cvelist.xml")
for nodeEntry in xmldoc.getElementsByTagName("entry"):                                                                  #for loop to get entry ID and and vulnerable SW
    entryid = nodeEntry.getAttribute("id")
    software = nodeEntry.getElementsByTagName("vuln:product")
    pubdate = nodeEntry.getElementsByTagName("vuln:published-datetime")[0]
    pubvalue = pubdate.childNodes[0].data[:10]
    lastmod = nodeEntry.getElementsByTagName("vuln:last-modified-datetime")[0]
    modvalue = lastmod.childNodes[0].data[:10]
    for nodeSoftware in software:                                                                                       #for loop to get vulnerable sw readable data
        score = nodeEntry.getElementsByTagName("cvss:score")[0]
        scorevalue = score.childNodes[0].data
        accvec = nodeEntry.getElementsByTagName("cvss:access-vector")[0]
        accvecval = accvec.childNodes[0].data
        acccomp = nodeEntry.getElementsByTagName("cvss:access-complexity")[0]
        acccompval = acccomp.childNodes[0].data
        authreq = nodeEntry.getElementsByTagName("cvss:authentication")[0]
        authreqval = authreq.childNodes[0].data
        confimp = nodeEntry.getElementsByTagName("cvss:confidentiality-impact")[0]
        confimpval = confimp.childNodes[0].data
        intimp = nodeEntry.getElementsByTagName("cvss:integrity-impact")[0]
        intimpval = intimp.childNodes[0].data
        availimp = nodeEntry.getElementsByTagName("cvss:availability-impact")[0]
        availimpval = availimp.childNodes[0].data
        summary = nodeEntry.getElementsByTagName("vuln:summary")[0]
        summaryval = summary.childNodes[0].data
        vulnsw = nodeSoftware.childNodes[0].data
        SQLstr = vulnsw[7:]  # Strips off prefix
        SQLinsert = "INSERT INTO cve_list (cve_id, software_package, pub_date, mod_date, score, access_vector, \
        access_complexity, authen, conf_impact, integ_impact, avail_impact, summary) VALUES \
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"                                                               # Defines SQL insert function to be used
        cur.execute(SQLinsert, (entryid, SQLstr, pubvalue, modvalue, scorevalue, accvecval, acccompval, authreqval,
                                confimpval, intimpval, availimpval, summaryval))                                        # Insert data  #Executes SQL statement in postgres
        conn.commit()

#Create Reference Table
cur.execute("CREATE TABLE cv2 AS SELECT * FROM cve_list;")
conn.commit()

#Delete Duplicates by checking package name and keeping first occurence of package
cur.execute("DELETE FROM cve_list USING cve_list cv2 WHERE cve_list.cve_id \
 = cv2.cve_id AND cve_list.software_package = cv2.software_package AND \
 cve_list.pub_date = cv2.pub_date AND cve_list.mod_date = cv2.mod_date AND \
 cve_list.key_column > cv2.key_column OR cve_list.cve_id = cv2.cve_id AND \
 cve_list.software_package = cv2.software_package AND cve_list.pub_date = cv2.pub_date AND \
 cve_list.mod_date < cv2.mod_date;")
conn.commit()

#Delete Reference Table
cur.execute("DROP TABLE cv2;")
conn.commit()

#parse data
xmldoc = minidom.parse("cvelist.xml")
for nodeEntry in xmldoc.getElementsByTagName("entry"):                                                                  #for loop to get entry ID and and vulnerable SW
    entryid = nodeEntry.getAttribute("id")
    software = nodeEntry.getElementsByTagName("vuln:product")
    for nodeSoftware in software:                                                                                       #for loop to get vulnerable sw readable data
        vulnsw = nodeSoftware.childNodes[0].data
        SQLstr = vulnsw[7:]                                                                                             #Strips off prefix
        SQLinsert = "INSERT INTO software_list (software_name) VALUES (%s)"                                             #Defines SQL insert function to be used
        cur.execute(SQLinsert, (SQLstr,))                                                                               #Insert data  #Executes SQL statement in postgres
        conn.commit()                                                                                                   #Saves change to database

#Create Reference Table
cur.execute("CREATE TABLE sl2 AS SELECT * FROM software_list;")
conn.commit()

#Delete Duplicates by checking package name and keeping first occurence of package
cur.execute("DELETE FROM software_list USING software_list sl2 WHERE software_list.software_name \
 = sl2.software_name AND software_list.key_column > sl2.key_column;")
conn.commit()

#Delete Reference Table
cur.execute("DROP TABLE sl2;")
conn.commit()

##################
##Mapping Import##
##################

#varibles
mappath = "http://iasecontent.disa.mil/stigs/xml/cvexref_u.xml"
mapxmlfile = "mapping.xml"


#Grab file to be used for nist website
mapfile = urllib.URLopener()
mapfile.retrieve(mappath, mapxmlfile)

#parse data
xmldoc = minidom.parse("mapping.xml")
for nodeEntry in xmldoc.getElementsByTagName("notice"):                                                                  #for loop to get required info
    iavmnum = nodeEntry.getAttribute("number")
    iavmseverity = nodeEntry.getAttribute("severity")
    iavmtitle = nodeEntry.getAttribute("title")
    cveid = nodeEntry.getElementsByTagName("cve")
    for nodeCVEid in cveid:                                                                                             #for loop to get each CVE that matches an IAVM
        cvelist = nodeCVEid.childNodes[0].data
        SQLinsert = "INSERT INTO cve_iavm (cve_item, iavm_item, severity, title) VALUES (%s, %s, %s, %s)"               #Defines SQL insert function to be used
        cur.execute(SQLinsert, (cvelist, iavmnum, iavmseverity, iavmtitle))                                             #Executes SQL statement in postgres
        conn.commit()                                                                                                   #Saves change to database

#Create Reference Table
cur.execute("CREATE TABLE mp2 AS SELECT * FROM cve_iavm;")
conn.commit()

#Delete Duplicates by checking package name and keeping first occurence of package
cur.execute("DELETE FROM cve_iavm USING cve_iavm mp2 WHERE cve_iavm.cve_item = mp2.cve_item \
AND cve_iavm.iavm_item = mp2.iavm_item AND cve_iavm.severity = mp2.severity AND \
cve_iavm.title = mp2.title AND cve_iavm.key_column > mp2.key_column;")
conn.commit()

#Delete Reference Table
cur.execute("DROP TABLE mp2;")
conn.commit()

#Close connection
conn.close()
