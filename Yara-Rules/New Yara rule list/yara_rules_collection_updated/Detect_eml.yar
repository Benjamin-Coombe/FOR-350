rule Detect_eml
{
    meta:
        description = "Detect Email EML file using common headers"
        author = "Modified for hex detection"
        date = "2025-12-01"
    strings:
        $eml_from = "From:" // Email From header
        $eml_subject = "Subject:" // Email Subject header
        $eml_date = "Date:" // Email Date header
    condition:
        ($eml_from and $eml_subject) or ($eml_from and $eml_date)
}
