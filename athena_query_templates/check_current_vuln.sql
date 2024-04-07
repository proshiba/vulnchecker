SELECT * FROM "vulndb"."current"
where
    "cvss_score" != 'N/A' and
    "cvss_string" like '%/AV:N/%' and
    (
        "cvss_score" like '7.%' or
        "cvss_score" like '8.%' or
        "cvss_score" like '9.%' or
        "cvss_score" like '10%'
    )
ORDER BY "cvss_score" desc
limit 1000;