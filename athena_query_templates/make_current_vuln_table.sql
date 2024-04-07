-- Locationのバケット名をしてください
CREATE EXTERNAL TABLE IF NOT EXISTS `vulndb`.`current` (
  `cve_id` string,
  `create_date` timestamp,
  `cve_src` string,
  `description` string,
  `cvss_string` string,
  `cvss_score` string,
  `reference` string
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe'
WITH SERDEPROPERTIES ('field.delim' = '\t')
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat' OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{{bucket}}/summary/current/'
TBLPROPERTIES ("skip.header.line.count"="1");
