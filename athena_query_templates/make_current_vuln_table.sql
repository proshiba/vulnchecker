CREATE EXTERNAL TABLE IF NOT EXISTS `vulndb`.`current` (
  `cve_id` string,
  `create_date` timestamp,
  `cvss_string` string,
  `cvss_score` string,
  `cve_src` string,
  `shortDesc` string,
  `vulnSW` string,
  `affectVersion` string,
  `fixedVersion` string,
  `TriggeredBug` string,
  `impact` string
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe'
WITH SERDEPROPERTIES ('field.delim' = '\t')
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat' OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{{bucket}}/enrich/current/'
TBLPROPERTIES ("skip.header.line.count"="1");
