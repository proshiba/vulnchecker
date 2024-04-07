import json
import datetime
import boto3
import os
import csv
import io
import yaml
from logging import getLogger, config as logconf

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
PROMPT_DIR = CURR_DIR+"/prompts"

LOG_CONF = CONF_DIR+"/log.conf"

_LINE_SEP = "<br />"

def get_yesterday():
    utcnow = datetime.datetime.utcnow()
    jstdelta = datetime.timedelta(hours=9)
    jstnow = utcnow+jstdelta
    onedaydelta = datetime.timedelta(days=1)
    yesterday = jstnow-onedaydelta
    yesterday_str = yesterday.strftime("%Y-%m-%d")
    return yesterday_str

def save_enrichdata_summary_csv(enrich_events, yesterday_str, s3bucket_name):
    s3 = boto3.resource('s3')
    s3bucket = s3.Bucket(s3bucket_name)
    month_of_yesterday = yesterday_str.rsplit("-", 1)[0]
    fname = "enrich/{}/{}.tsv".format(month_of_yesterday, yesterday_str)
    fname_current_only_file = "enrich/current/{}.tsv".format(yesterday_str)
    headers = ["cve_id", "create_date", "cvss_string", "cvss_score", "cve_src", "shortDesc", "vulnSW", "affectVersion", "fixedVersion", "TriggeredBug", "impact"]
    sio = io.StringIO()
    writer = csv.writer(sio, delimiter='\t')
    writer.writerow(headers)
    for each_change in enrich_events:
        each_csv_data=[]
        for each_column_name in headers:
            if each_column_name in each_change:
                each_column = each_change.get(each_column_name)
            else:
                each_column = "N/A"
            if isinstance(each_column, list):
                each_column_str = _LINE_SEP.join(each_column)
            elif isinstance(each_column, dict):
                each_column_str = json.dumps(each_column)
            else:
                each_column_str = str(each_column)
            each_column_str = each_column_str.replace("\t", "    ")
            each_column_str = _LINE_SEP.join(each_column_str.splitlines())
            each_csv_data.append(each_column_str)
        writer.writerow(each_csv_data)
    csv_data = sio.getvalue()
    sio.close()
    logger.info("savesummary{}".format(fname))
    s3bucket.put_object(Key=fname, Body=csv_data)
    s3bucket.put_object(Key=fname_current_only_file, Body=csv_data)

def save_rawdata_summary_csv(s3bucket, yesterday_str, cvechanges):
    month_of_yesterday = yesterday_str.rsplit("-", 1)[0]
    fname = "summary/{}/{}.tsv".format(month_of_yesterday, yesterday_str)
    headers = ["cve_id", "create_date", "cve_src", "description", "cvss_string", "cvss_score", "reference"]
    sio = io.StringIO()
    writer = csv.writer(sio, delimiter='\t')
    writer.writerow(headers)
    for each_change in cvechanges:
        each_csv_data=[]
        for each_column_name in headers:
            if each_column_name in each_change:
                each_column = each_change.get(each_column_name)
            else:
                each_column = "N/A"
            if isinstance(each_column, list):
                each_column_str = _LINE_SEP.join(each_column)
            elif isinstance(each_column, dict):
                each_column_str = json.dumps(each_column)
            else:
                each_column_str = str(each_column)
            each_column_str = each_column_str.replace("\t", "    ")
            each_column_str = _LINE_SEP.join(each_column_str.splitlines())
            each_csv_data.append(each_column_str)
        writer.writerow(each_csv_data)
    csv_data = sio.getvalue()
    sio.close()
    logger.info("savesummary{}".format(fname))
    s3bucket.put_object(Key=fname, Body=csv_data)

def get_nvd_changes(yesterday_str):
    logger.info("toSaveBucket:{}".format(os.environ["s3bucket"]))
    cvechanges = nvd_util.get_nvd_change_by_date(yesterday_str)
    logger.info("all events Length:{}".format(len(cvechanges)))
    cvechanges = [ nvd_util.CveChange(each) for each in cvechanges ]
    results = [ each.to_dict() for each in cvechanges ]
    return results

def save_rawdata(cvechanges, yesterday_str, s3bucket_name):
    s3 = boto3.resource('s3')
    s3bucket = s3.Bucket(s3bucket_name)
    for each_change in cvechanges:
        each_data   = json.dumps(each_change)
        each_fname  = "{}/{}.json".format(yesterday_str, each_change["cve_id"])
        logger.info("save to {}/{}".format(s3bucket_name, each_fname))
        s3bucket.put_object(Key=each_fname, Body=each_data)
    save_rawdata_summary_csv(s3bucket, yesterday_str, cvechanges)

def main_func_for_parse_openai(nvd_changes, openai_config, s3bucket_name):
    chat = openai_util.start_chat(openai_config)
    omit_config = openai_config["omit_property"]
    omit_max_length = omit_config["max_length"]
    omit_use_which = omit_config["use_which"]
    results = []
    for each_change in nvd_changes:
        description = each_change["description"]
        for i in range(3): # retry 3 times
            try:
                each_result = chat.ask_with_omit_input(description, omit_max_length, omit_use_which)
                logger.info("openai response -> {}".format(each_result))
                each_enrich_info = json.loads(each_result)
                results.append(dict(**each_change, **each_enrich_info))
                break
            except Exception as e:
                logger.error("openai error at {} times".format(i))
                logger.exception(e)
    return results

def grep_target_event(nvd_changes, min_cvss_score):
    min_cvss_score = float(min_cvss_score)
    logger.info("rawevent Num -> {}. and grep CVSS Score is higher than {}".format(len(nvd_changes), min_cvss_score))
    results = []
    for each_changes in nvd_changes:
        cvss_score = each_changes["cvss_score"]
        if each_changes["description"] == "N/A": # skip if no description
            continue
        elif not(cvss_score == "N/A") and isinstance(cvss_score, float):
            if cvss_score >= min_cvss_score:
                results.append(each_changes)
    logger.info("target event Num -> {}".format(len(results)))
    return results

def parse_config():
    config = {}
    with open(CONF_DIR+"/config.yaml") as f:
        config = yaml.safe_load(f)
    return config

def main():
    config = parse_config()
    s3bucket_name = config["storage"]["s3"]["bucket"]
    yesterday_str = get_yesterday()

    # get nvd events at yesterday
    nvd_changes = get_nvd_changes(yesterday_str)
    save_rawdata(nvd_changes, yesterday_str, s3bucket_name)

    # parse by openai if needed
    openai_config = config["openai_parse"]
    important_changes = grep_target_event(nvd_changes, openai_config["min_cvss_score"])
    if openai_config["enable"]:
        enrich_events = main_func_for_parse_openai(important_changes, openai_config, s3bucket_name)
        save_enrichdata_summary_csv(enrich_events, yesterday_str, s3bucket_name)

if __name__ == "__main__":
    logconf.fileConfig(LOG_CONF)
    logger = getLogger()
    import nvd_util
    import openai_util
    main()
else:
    logger = getLogger()
    import nvd_util
    import openai_util
