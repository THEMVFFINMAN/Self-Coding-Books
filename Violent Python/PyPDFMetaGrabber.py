import pyPdf, argparse, os.path, calendar
from pyPdf import PdfFileReader

def printMeta(fileName):
    pdfFile = PdfFileReader(file(fileName, 'rb'))
    docInfo = pdfFile.getDocumentInfo()
    print '\n[*] PDF MetaData For: {0}\n'.format(str(fileName))
    for metaItem in docInfo:
        if docInfo[metaItem][0] == "D":
            time = docInfo[metaItem][2:16]
            time = calendar.month_name[int(time[4:6])] + ' ' + time[6:8] + ', ' + time[:4] + ' at ' + time[8:10] + ':' + time[10:12] + ':' + time[12:14]
            print '[+] {0:20}{1}'.format(metaItem.replace('/', '') + ':', time)
        else:
            print '[+] {0:20}{1}'.format(metaItem.replace('/', '') + ':', docInfo[metaItem])

def main():
    parser = argparse.ArgumentParser(description = "A pdf Metadata printer")
    parser.add_argument('-F', type=str, help='a pdf file')

    args = parser.parse_args()

    pdfFile = args.F
    

    if pdfFile == None:
	print parser.print_help()
	exit(0)
    elif os.path.isfile(pdfFile):
        printMeta(pdfFile)
    else:
        print "File does not exist!"
        exit(0)

if __name__ == "__main__":
    main()
