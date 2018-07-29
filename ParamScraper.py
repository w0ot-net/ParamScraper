from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import *;
from java.awt.event import MouseListener
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing import JMenuItem
from javax.swing import SwingWorker
from javax.swing.table import AbstractTableModel;
from java.util.concurrent import ExecutionException
from threading import Lock

from bs4 import BeautifulSoup
import chardet

"""
- ParamScraper by Chris Anastasio 7-21-18
- Created to assist in bug hunting
- This extension is proof that you can slap together other peoples code
    together without knowing what you're doing and make something ~useful.
    A lot of the code in here is borrowed heavily from the CustomLogger
    example by portswigger and theawesome  Wsdler plugin. Here is a list of
    links which I found helpful in some way while working on this:
        - https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=12&ved=0ahUKEwihwd_Aw6DcAhUqqlkKHYgpCmw4ChAWCC4wAQ&url=
        - https%3A%2F%2Fwww.owasp.org%2Fimages%2F9%2F9f%2FExtending-Burp-with-Python.pptx&usg=AOvVaw1Ya2e78oZ8-JaUbJ3Wyzoz (extending burp owasp powerpoint)
        - https://realpython.com/setting-up-sublime-text-3-for-full-stack-python-development/ (getting sublime/python env together)
        - https://laconicwolf.com/2018/04/13/burp-extension-python-tutorial/ (exceptions_fix.py)
        - http://blog.opensecurityresearch.com/2014/03/extending-burp.html (custom passive scanner)
        - https://github.com/OpenSecurityResearch/CustomPassiveScanner/blob/master/CustomPassiveScanner.py (getting beautiful soup working)
        - https://allfro.github.io/BurpKit/API/callbacks-api/#customizeuicomponentcomponent-component (got a bunch of examples)
        - https://github.com/NetSPI/Wsdler/blob/e4801a2925d47dcc309cdd178d860cabecc72933/src/main/java/burp/Menu.java (help with context menu)
        - https://github.com/lanxia/PyHack/blob/master/bing.py (help with context menu)
        - https://lab26.net/static/files/mznlab_customTab_example_py.txt  (jython mouse listener)
- The intended work flow is, as requests worth active scanning are identified
    to also send them to the ParamScraper. If extra parameters are found
    in the request's response then the request should be rescanned with
    the extra parameters.
    Requests with extra parameters should be scanned alongside (rather than
    instead of) organic requests. This is because there is a chance that
    adding erroneous parameters to a request could cause it to malfunction
    and possibly cause the hacker to miss a bug.
- Greetz to Illumant, Luis, Fabius, Ben, Justin and all others who have
    helped me become a better hacker.
"""

class BurpExtender(IBurpExtender, ITab, IMessageEditorController,
                   AbstractTableModel, IContextMenuFactory):

    #
    # implement IBurpExtender
    #

    def	registerExtenderCallbacks(self, this_callbacks):

        # stolen from activescan++
        global callbacks, helpers
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()

        # keep a reference to our callbacks object
        self._callbacks = this_callbacks

        # obtain an extension helpers object
        self._helpers = this_callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("ParamScraper")

        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTable = Table(self, self._helpers)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request With Scraped Parameters",
                    self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # register ourself as a context menu...thing
        callbacks.registerContextMenuFactory(self)

        return

    # stolen from https://github.com/NetSPI/Wsdler/blob/e4801a2925d47dcc309cdd178d860cabecc72933/src/main/java/burp/Menu.java
    def createMenuItems(self, contextMenu):
        menuList = ArrayList()
        requestResponse =  contextMenu.getSelectedMessages()[0]
        mouseListener = CustomMouseListener(self,
                                            self._helpers,
                                            requestResponse)
        item = JMenuItem("Scrape Parameters")
        item.addMouseListener(mouseListener)
        menuList.add(item)
        return menuList

    #
    # implement ITab
    #

    def getTabCaption(self):
        return "ParamScraper"

    def getUiComponent(self):
        return self._splitpane

    def addLogEntry(self, messageInfo):
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry("Processing...", self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "# Scraped Parameters"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry.getExtraParamCount()
            #return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# Extend MouseListener so we can add it to the context menu
#

class CustomMouseListener(MouseListener):
    """Extends the MouseListener class"""
    # https://lab26.net/static/files/mznlab_customTab_example_py.txt

    def __init__(self, extender, helpers, requestResponse):
        self._extender          = extender
        self._helpers           = helpers
        self._requestResponse   = requestResponse

    def mouseClicked(self, e):
        pass

    def mouseEntered(self, e):
        pass

    def mouseExited(self, e):
        pass

    def mousePressed(self, e):
        pass

    def mouseReleased(self, e):
        worker = Worker(self._extender, self._helpers, self._requestResponse)
        worker.execute()

#
# functions grabbing the extra parameters
#

class ParamScraper():
    def __init__(self, extender, helpers, requestResponse):
        self._extender          = extender
        self._helpers           = helpers
        self._requestResponse   = requestResponse
        self._extraParamCount   = 0

    # stolen from activescan++
    def safeBytesToString(self, bytes):
        if bytes is None:
            bytes = ''
        return self._helpers.bytesToString(bytes)

    def safeStringToBytes(self, string):
        if string is None:
            string = ''
        return self._helpers.stringToBytes(string)

    def getOriginalParameters(self):
        """returns a dictionary of the param/value paris based
        on the initial request"""

        # initialize dictionary of parameter/value pairs
        params = {}

        # this returns a list of IParameter objects
        originalParams = self._helpers.analyzeRequest(self._requestResponse) \
                                      .getParameters()

        # it's a java arrayList so we change to a python list
        originalParams = list(originalParams)

        # loop over each IParameter object
        for param in originalParams:

            # store it in a dictionary with the name as the key
            params[param.getName()] = param.getValue()

        return params

    def weirdDecode(self, value):


        # encode the value no matter what
        encoding = "utf-8"
        value = value.encode(encoding)

        # try to detect encodng
        # https://stackoverflow.com/questions/33966590/

        try:
            encoding = chardet.detect(value)
        except Exception as e:
            print e
            print "chardet couldn't detect encoding"

        e = None
        decodeCount = 0
        while e is None:
            try:
                value = value.decode(encoding)
                decodeCount += 1
            except Exception as e:
               # if we hit an exception that means we're decoded as far as
               # we can go
               pass

        return value

    def getParamsFromResponse(self):
        """Finds all input tags returns a dctionary
        of parameter names and values.
        Loops through all <input> tags and reads the 'name' or 'id'
        there may be other that we are missing.
        """



        # get the response as a string
        response = self.safeBytesToString(self._requestResponse.getResponse())

        # beautiful soup object
        soup = BeautifulSoup(response, "html.parser")

        # tag attributes that contain parameter names
        tag_attrs = ("name", "id")

        # track if "name" or "id" attr was found in the tag
        noneMatched = True

        # input types that we don't care about
        dontCareInputsList  = ("radio", "checkbox")

        # initialize dictionary of parameter/value pairs
        params = {}

        # store the input tags parsed by bs
        #! does this need to be made case insensitive?
        input_tags  = soup.find_all("input")

        # loop over all the tags that beautiful soup found
        for tag in input_tags:
            # ignore the types that we don't care about such
            # as checkboxes and radio buttons
            if ((tag.get("type") is not None) and
                (tag.get("type").lower() in dontCareInputsList)):
                continue
            # flag to
            noneMatched = True

            # loop over each tag to retrieve its value
            for attr in tag_attrs:

                # get the parameter name from each tag
                param = tag.get(attr)

                # get the parameter value if it has one
                value = tag.get("value")
                if value is None: value = ""
                if param is not None:
                    '''
                    print "=========================="
                    print "undecoded param: " + param
                    print "undecoded value: " + value
                    param = self.weirdDecode(param)
                    value = self.weirdDecode(value)
                    print "--------------------------"
                    '''
                    params[param] = value
                    '''
                    print "decoded param: " + param
                    print "decoded value: " + value
                    print params
                    print "=========================="
                    print ""
                    '''
                    noneMatched = False

            # not sure why i have this
            if noneMatched:
                continue

        # return the dictionary of params
        return params

    def getExtraParameters(self, originalParams, paramsFromResponse):
        """Returns the parameter names which were found in the response but were not already in the original request.
        """

        # initialize list to store the new parameter names
        extraParams = []

        # loop over all the parameters found in the response
        for param in paramsFromResponse.keys():

            # check if that's in the original parameters already
            if param not in originalParams.keys():

                # if it's not in there then add it to our list
                extraParams.append(param)

        # keep track of how many new parameters we found
        self._extraParamCount = len(extraParams)

        return extraParams

    def updateRequest(self, paramsFromResponse, extraParams):
        """Return a new request (bytearray) with the scraped parameters added
        to the request. TODO: check if it's a POST/GET and add accordingly.
        For now rverything goes in the URL.
        """

        # https://portswigger.net/burp/extender/api/constant-values.html
        PARAM_BODY = 0x01
        PARAM_URL  = 0x00

        request = self._requestResponse.getRequest()

        # loop over all the unique parameters that we scraped from the response
        for param in extraParams:

            # create a corresponding burp IParameter
            # weird stuff happens if there are spaces. not sure if other
            # characters will cause problems, but I think URL encoding could
            # interfere with the scanner so I'm trying to avoid it
            value = paramsFromResponse[param].replace(' ', '+')
            burpParam = helpers.buildParameter(param,
                                               value,
                                               PARAM_URL)
            # add it to the request
            request = helpers.addParameter(request, burpParam)

        return request

    def getExtraParamCount(self):
        return self._extraParamCount

    def getRequestWithScrapedParameters(self):
        response = self._requestResponse.getResponse()
        responseStr = self.safeBytesToString(response)
        request = self._requestResponse.getRequest()
        #test = safe_bytes_to_string(response)

        # returns dictionary of param/value pairs
        originalParams = self.getOriginalParameters()

        # returns dictionary of param/value pairs that we scraped
        paramsFromResponse = self.getParamsFromResponse()

        # returns a list of the parameter names we which were not part of the
        # original parameters
        extraParams = self.getExtraParameters(originalParams, paramsFromResponse)

        # create the new request bytes
        requestWithScrapedParameters = self.updateRequest(paramsFromResponse,
                                                     extraParams)

        return requestWithScrapedParameters

#
# extend JTable to handle cell selection
#

class Table(JTable):
    def __init__(self, extender, helpers):
        self._extender  = extender
        self._helpers   = helpers
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):

        # get a handle on the current log
        logEntry        = self._extender._log.get(row)
        requestResponse = logEntry._requestResponse
        parser          = ParamScraper(self._extender,
                                       self._helpers,
                                       requestResponse)
        request         = parser.getRequestWithScrapedParameters()
        response        = requestResponse.getResponse()



        logEntry.setExtraParamCount(parser.getExtraParamCount())
        self._extender._requestViewer.setMessage(request, True)
        self._extender._responseViewer.setMessage(response, False)
        self._extender._currentlyDisplayedItem = requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)


#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, extraParamCount, requestResponse, url):
        self._extraParamCount   = extraParamCount
        self._requestResponse   = requestResponse
        self._url               = url

    def getExtraParamCount(self):
        return self._extraParamCount

    def setExtraParamCount(self, num):
        self._extraParamCount = num

#
# implement SwingWorker
#

class Worker(SwingWorker):
    """Implement SwingWorker class so that we can actually do stuff after the
    button in the context menu is clicked. Without this we'll get an error
    about trying to do stuff in the swing thread"""

    def __init__(self, extender, helpers, requestResponse):
        self._extender          = extender
        self._helpers           = helpers
        self._requestResponse   = requestResponse

    def doInBackground(self):
        """Add the request to our ParamScraper tab"""

        # check if the response is empty
        # I think this is always going to be the case
        response = self._requestResponse.getResponse()
        if response is None:

            # make the request so that we can read the response
            # and parse the parameters
            self._requestResponse = callbacks.makeHttpRequest(
                self._requestResponse.getHttpService(),
                self._requestResponse.getRequest())

            # store the response
            response = self._requestResponse.getResponse()

            # create parser objected just to get param count :(
            # need to find a better wayyy
            parser = ParamScraper(self._extender, self._helpers, self._requestResponse)

            # add log entry for the ORIGINAL request
            self._extender.addLogEntry(self._requestResponse)

            # get a handle on the latest current log entry
            logEntry = self._extender._log.get(self._extender._log.size() - 1)

            # update the param count for the log entry
            parser.getRequestWithScrapedParameters() # has to run to get count
            logEntry.setExtraParamCount(parser.getExtraParamCount())

        if response is None:
            print "can't get response from this request"
        return

    def done(self):
        # stolen from https://wiki.python.org/jython/SwingWorker
        try:
            self.get()

        #raise exception if abnormal completion
        except ExecutionException, e:
            print e
