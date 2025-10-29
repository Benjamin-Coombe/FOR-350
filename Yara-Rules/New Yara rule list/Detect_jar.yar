rule Detect_jar
{
    meta:
        description = "Regex detect pattern: .jar"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $regex = /\.jar/i
    condition:
        $regex
}
