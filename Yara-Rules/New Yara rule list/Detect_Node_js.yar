rule Detect_Node_js
{
    meta:
        description = "String detect pattern: Node.js"
        author = "ChatGPT"
        date = "2025-10-29"
    strings:
        $a = "Node.js" nocase
    condition:
        $a
}
