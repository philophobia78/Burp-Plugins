from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from array import array
import re

#
# This plugin will replay each request without Cookie and Authorization headers and report the issue if the request is successful (Code 200)
# Author : David Bloom <@philophobia78>
#

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Unauthenticated Request Check")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def toProcess(self,baseRequestResponse):
	# Scan only if base request is successful
	code = self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode()
        if code == 200 :
            return True
        return False

    def removeHeader(self, headerStr, headerName):
        headerStr = re.sub('\r\n'+headerName+':.*?$',"\r", headerStr, flags=re.I|re.M)
        return headerStr
        

    def doPassiveScan(self, baseRequestResponse):
        if self.toProcess(baseRequestResponse) == False:
            return None
            
        request = self._helpers.bytesToString(baseRequestResponse.getRequest())
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()

        self.stdout.println("Scanning: "+url)
        results = []
            
        request = self.removeHeader(request, "Cookie")
        request = self.removeHeader(request, "Authorize")
        
        checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(request))
        code = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
        if code == 200:
            results.append("Page accessible without authentication")
        
        if len(results) == 0:
            return None

        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
            "Unauthenticated request successful",
            '<br>'.join(results),
            "High")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getUrl() == newIssue.getUrl():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
