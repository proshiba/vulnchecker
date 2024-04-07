import re, json
import requests
import cvss
from logging import getLogger

logger = getLogger()

BASE_URL="https://services.nvd.nist.gov/rest/json/cvehistory/2.0/"

class CveChange(object):
    def __init__(self, cvechange):
        self._raw = cvechange["change"]
        self._parse_rawdata()
    
    def to_dict(self):
        return {
            "cve_id"  : self.cve_id,
            "cve_src" : self.cve_src,
            "create_date" : self.cve_created,
            "description" : self.cve_description,
            "cvss_string" : self.cvss_string,
            "cvss_score" : self.cvss_score,
            "reference" : self.references
        }

    def to_list(self):
        return [
            self.cve_id,
            self.cve_created,
            self.cve_src,
            self.cve_description,
            self.cvss_string,
            self.cvss_score,
            self.references
        ]

    def to_json(self, json_indent=None):
        if json_indent:
            return json.dumps(self.to_dict(), indent=json_indent)
        else:
            return json.dumps(self.to_dict())
    
    def _parse_rawdata(self):
        self.cve_id = self._raw["cveId"]
        self.cve_src = self._raw["sourceIdentifier"]
        self.cve_created = self._raw["created"]
        self.cve_description = "N/A"
        self.cvss_string = "N/A"
        self.cvss_score = "N/A"
        self.references = []
        for each_detail in self._raw["details"]:
            each_detail_type = each_detail["type"]
            if not "newValue" in each_detail:
                continue
            if each_detail_type == "Description":
                self.cve_description = each_detail["newValue"]
            elif each_detail_type == "Reference":
                self.references.append(each_detail["newValue"])
            elif each_detail_type.startswith("CVSS V3"):
                pt = "AV:[^ ]+/A:[A-Z]$"
                cvss_string_match = re.search(pt, each_detail["newValue"])
                if cvss_string_match:
                    cvss_string = cvss_string_match.group()
                    if each_detail_type=="CVSS V3.0":
                        cvss_string = "CVSS:3.0/"+cvss_string
                    elif each_detail_type=="CVSS V3.1":
                        cvss_string = "CVSS:3.1/"+cvss_string
                    else:
                        continue
                    _cvss = cvss.CVSS3(cvss_string)
                    scores = _cvss.scores()
                    self.cvss_string = cvss_string
                    self.cvss_score = scores[0]



def get_nvd_change(earliest=None, latest=None, start_index=0):
    base = BASE_URL
    if earliest and latest:
        url = "{}?changeStartDate={}&changeEndDate={}&startIndex={}".format(base, earliest, latest, start_index)
    else:
        url = "{}?startIndex={}".format(base, start_index)
    logger.info("access to -> "+url)
    res = requests.get(url)
    return json.loads(res.text)

def is_rejected_event(cvechange):
    if "CVE Rejected" in cvechange["change"]["eventName"]:
        return True
    return False

def get_nvd_change_by_date(targetdate):
    results = []
    start_index = 0
    earliest = targetdate+"T00:00:00.000%2B09:00"
    latest = targetdate+"T23:59:59.999%2B09:00"
    each_results = get_nvd_change(earliest, latest)
    results.extend(each_results["cveChanges"])
    total_results = each_results["totalResults"]
    start_index = each_results["resultsPerPage"]
    while start_index<total_results:
        each_results = get_nvd_change(earliest, latest, start_index)
        for cvechange in each_results["cveChanges"]:
            if is_rejected_event(cvechange):
                continue
            results.append(cvechange)
        results.extend(each_results["cveChanges"])
        start_index += each_results["resultsPerPage"]
    return results
