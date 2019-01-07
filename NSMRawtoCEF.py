#!/usr/bin/python
import xlrd
import itertools
from time import strptime
import sys
import os

# Configuration
nsm_host = ''          # McAfee NSM Hostname
nsm_filename = ''      # Input file that holds raw NSM alerts
graylog_host = ''      # Graylog Host Name
# End of Configuration

# Variables
time = []
sigID = []
name = []
severity = []
src = []
shost = []
spt = []
dst = []
dhost = []
dpt = []
dvchost = []
act = []
cnt = []
cat = []
alertID = []
# End of Variables

def convert_raw_cef(filename):
    workbook = xlrd.open_workbook(filename)
    worksheet = workbook.sheet_by_index(0)
    numRows = worksheet.nrows
    numCols = worksheet.ncols

    for currRow in range(4, numRows, 1):
        for currCol in range(0, numCols, 1):
            if currCol == 0:
                severityData = worksheet.cell_value(currRow, currCol)
                severity.append(severityData)

            elif currCol == 1:
                nameData = worksheet.cell_value(currRow, currCol)
                name.append(nameData)

            elif currCol == 2:
                timeData = worksheet.cell_value(currRow, currCol)
                time.append(timeData)

            elif currCol == 4:
                actData = worksheet.cell_value(currRow, currCol)
                act.append(actData)

            elif currCol == 5:
                cntData = worksheet.cell_value(currRow, currCol)
                cnt.append(int(cntData))

            elif currCol == 7:
                alertIDData = worksheet.cell_value(currRow, currCol)
                alertIDCleanData = alertIDData.replace('{', '').replace('}', '')
                alertID.append(alertIDCleanData)

            elif currCol == 9:
                sigIDData = worksheet.cell_value(currRow, currCol)
                sigID.append(sigIDData)

            elif currCol == 11:
                catData = worksheet.cell_value(currRow, currCol)
                cat.append(catData)

            elif currCol == 12 :
                srcData = worksheet.cell_value(currRow, currCol)
                src.append(srcData)

            elif currCol == 13:
                sptData = worksheet.cell_value(currRow, currCol)
                spt.append(int(sptData))

            elif currCol == 15:
                shostData = worksheet.cell_value(currRow, currCol)
                if shostData:
                	shost.append(shostData)
                else:
                	shost.append("n/a")

            elif currCol == 17:
                dstData = worksheet.cell_value(currRow, currCol)
                dst.append(dstData)

            elif currCol == 18:
                dptData = worksheet.cell_value(currRow, currCol)
                dpt.append(int(dptData))

            elif currCol == 20:
                dhostData = worksheet.cell_value(currRow, currCol)
                if dhostData:
                	dhost.append(dhostData)
                else:
                	dhost.append("n/a")

            elif currCol == 23:
                dvchostData = worksheet.cell_value(currRow, currCol)
                dvchost.append(dvchostData)


    # This will convert "Tue Apr 03 03:22:40 UTC 2018" to "Apr 03 03:22:40"
    injectionTime = [] 
    for timeStamp in time:
        temp = str(timeStamp)
        injectionTime.append(temp[4:-9])


    # This will convert "Tue Apr 03 03:22:40 UTC 2018" to "2018-04-02 09:12:39 UTC"
    start = []
    for timeStamp in time:
        month = strptime(timeStamp[4:7], '%b').tm_mon
        m = str(month).zfill(2) 
        start.append(timeStamp[-4:]+ '-' + str(m) + '-' + timeStamp[8:-5])

    
    with open('cef.txt', 'w+') as cef_write:
        if sys.version_info<(3,0,0):
            print ("you are using python v2. Please see the results in <cef.txt>")

        	# Unite data from all the lists to form a CEF compatible message
            for inTime,signature,msg,svrty,sip,sname,sprt,dip,dname,dprt,sensor,action,strt,count,category,alrtID in itertools.izip_longest(injectionTime,sigID,name,severity,src,shost,spt,dst,dhost,dpt,dvchost,act,start,cnt,cat,alertID):
                output = str("<117>%s %s SyslogAlertForwarder: CEF:0|McAfee|Network Security Manager|8.3.7|%s|%s|%s|src=%s shost=%s spt=%s dst=%s dhost=%s dpt=%s dvc=100.66.60.23 dvchost=%s act=%s start=%s cnt=%s cs1Label=Alert_Type cs1=Signature cat=%s cs2Label=Alert_Sub_Category cs2=n/a flexString1Label=Alert_ID flexString1=%s" % (inTime, nsm_host, signature, msg, svrty, sip, sname, sprt, dip, dname, dprt, sensor, action, strt, count, category, alrtID))
                cef_write.write(output)
                cef_write.write("\n")
        
        else:
            print ("you are using python v3. Please see the results in <cef.txt>")
            
            # Unite data from all the lists to form a CEF compatible message
            for inTime,signature,msg,svrty,sip,sname,sprt,dip,dname,dprt,sensor,action,strt,count,category,alrtID in zip(injectionTime,sigID,name,severity,src,shost,spt,dst,dhost,dpt,dvchost,act,start,cnt,cat,alertID):
                output = str("<117>%s %s SyslogAlertForwarder: CEF:0|McAfee|Network Security Manager|8.3.7|%s|%s|%s|src=%s shost=%s spt=%s dst=%s dhost=%s dpt=%s dvc=100.66.60.23 dvchost=%s act=%s start=%s cnt=%s cs1Label=Alert_Type cs1=Signature cat=%s cs2Label=Alert_Sub_Category cs2=n/a flexString1Label=Alert_ID flexString1=%s" % (inTime, nsm_host, signature, msg, svrty, sip, sname, sprt, dip, dname, dprt, sensor, action, strt, count, category, alrtID))
                cef_write.write(output)
                cef_write.write("\n")

if __name__ == '__main__':
    result_data = convert_raw_cef(nsm_filename)
    os.system('cat cef.txt |   while read -r line ; do echo "$line" | nc -v -t -w 100ms %s 12201;   done;' %graylog_host)
