import json,sys,time,os,csv,re,json

#Check no of argurements before running script
if len(sys.argv)<3:
    sys.exit('Usage: %s Folder to search, Report Output, IgnoreSignature(Optional)' % sys.argv[0])

folderPath = sys.argv[1]
folderPath = "C:\\Users\\Rupert Tan\\Dropbox\Sem 6\\Cuckoo\\Reports"
savePath = sys.argv[2]
savePath = "C:\\Users\\Rupert Tan\\Dropbox\Sem 6\\Cuckoo\\reportSummary.json"
ignoreSigList = []
urlScannedList = []
topDomain = {}
component = {}
subDomain = {}
output = {}
if len(sys.argv)==4:
    ignoreSigFile = sys.argv[3]
    ignoreSigFile = "C:\\Users\\Rupert Tan\\Dropbox\Sem 6\\Cuckoo\\ignoreSig.csv"
    if ignoreSigFile.lower().endswith('.csv'):
        with open(ignoreSigFile) as csvfile:
            csvreader = csv.reader(csvfile)
            ignoreSigList = next(csvreader)
    else:
        sys.exit('Error: IgnoreSignature must be a CSV file')
else:
    ignoreSigList = []

#Open directory, look for JSON files
directoryFiles = os.listdir(folderPath)
reportFiles = []
noOfFiles = 0
for files in directoryFiles:
    if files.lower().endswith('.json'):
        reportFiles.append(files)
        noOfFiles += 1
print "Found "+str(noOfFiles)+" files"

for filePath in reportFiles:
    with open(folderPath+"\\"+filePath) as json_file:
        data = json.load(json_file)
        urlScanned = data["target"]["url"]
        
        #HTTPS
        if re.match('^https://[\w]+\.[\w]+$',urlScanned):
            #No wwww.
            urlScanned = "https://www."+urlScanned[8:]
        #HTTP
        if re.match('^http://[\w]+\.[\w]+$',urlScanned):
            #No wwww.
            urlScanned = "http://www."+urlScanned[7:]
        #NO Protocol
        if re.match('^www\.[a-zA-Z0-9]+\..+',urlScanned):
            urlScanned = "http://"+urlScanned
        elif re.match('^[\w]+\.[a-zA-Z0-9]+\..+',urlScanned):
            #Sub-domain
            urlScanned = "http://"+urlScanned
        elif re.match('^[a-zA-Z0-9]+\..+',urlScanned):
            urlScanned = "http://www."+urlScanned

        if urlScanned not in urlScannedList:
            #perform analytics & add urlScanned to list
            urlScannedList.append(urlScanned)
            try:
                signatures = data["signatures"]
                sigDetected = []
                for signature in signatures:
                    if signature["name"] not in ignoreSigList:
                        sigDetected.append(signature["name"])
                data = {}
                if len(sigDetected)>0:
                    data["status"] = "Malicious"
                else:
                    data["status"] = "Safe"
                data["noOfSig"] = str(len(sigDetected))
                data["signatures"] = sigDetected
                
                #Classify the url category, build json output
                if re.match('https?://www\.[\w]+\.[\w]+[\.[\w]+]?',urlScanned):
                    topDomain[urlScanned] = data
                elif re.match('https?://[\w]+\.[\w]+\.[\w]+[\.[\w]+]?/.+',urlScanned):
                    component[urlScanned] = data
                elif re.match('https?://[\w]+\.[\w]+\.[\w]+[\.[\w]+]?',urlScanned):
                    subDomain[urlScanned] = data
            except(KeyError):
                print "Error: URL wasn't scan with signatures,"+filePath
        else:
            #skip report file
            print "URL duplicate, skipping"
output["Top-Domain"] = topDomain
output["Sub-Domain"] = subDomain
output["Component"] = component
outputJson = json.dumps(output)
print "Completed"

reportSummaryFile = open(savePath,"w")
reportSummaryFile.write(outputJson)
reportSummaryFile.close()