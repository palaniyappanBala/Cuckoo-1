import json,sys,time,os,csv
from tabulate import tabulate

if len(sys.argv)<3:
    sys.exit('Usage: %s Folder to search, Report Output, IgnoreSignature(Optional)' % sys.argv[0])

folderPath = sys.argv[1]
folderPath = "C:\\Users\\Rupert Tan\\Dropbox\Sem 6\\Cuckoo\\Reports"
savePath = sys.argv[2]
savePath = "C:\\Users\\Rupert Tan\\Dropbox\Sem 6\\Cuckoo\\reportSummary.txt"
ignoreSigList = []

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

directoryFiles = os.listdir(folderPath)
reportFiles = []
noOfFiles = 0
for files in directoryFiles:
    if files.lower().endswith('.json'):
        reportFiles.append(files)
        noOfFiles += 1

print "Found "+str(noOfFiles)+" files"

headers = ["URL","State","Comment"]
table = []
i = 1
for filePath in reportFiles:
    startTime = time.time()
    with open(folderPath+"\\"+filePath) as json_file:
        indivList = []
        sigDetected = []
        data = json.load(json_file)
        urlScanned = data["target"]["url"]
        indivList.append(urlScanned)
        try:
            signatures = data["signatures"]
            if len(signatures)>0:
                individualWebsiteSignatures = ""
                #for signature in signatures[:-1]:
                    #if signature["name"] not in ignoreList:
                        #individualWebsiteSignatures += signature["name"]+","
                #individualWebsiteSignatures += signatures[-1]["name"]
                for signature in signatures:
                    if signature["name"] not in ignoreSigList:
                        sigDetected.append(signature["name"])

                if len(sigDetected)>0:
                    indivList.append("Malicious")
                    for sig in sigDetected[:-1]:
                        individualWebsiteSignatures += sig+","
                    individualWebsiteSignatures += sigDetected[-1]
                    indivList.append(individualWebsiteSignatures)
                else:
                    indivList.append("Safe")
                    indivList.append("")
            else:
                indivList.append("Safe")
                indivList.append("")
        except(KeyError):
            indivList.append("Error")
            indivList.append("URL wasn't scan with signatures,"+filePath)
        table.append(indivList)
    print str(i)+"/"+str(noOfFiles)+" Time Taken: "+ str(time.time()-startTime) + " seconds"
    i += 1

output = tabulate(table, headers,tablefmt="simple")
print output

reportSummaryFile = open(savePath,"w")
reportSummaryFile.write(output)
reportSummaryFile.close()