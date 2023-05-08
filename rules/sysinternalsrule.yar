rule sysinternals_tools_hex
{
    meta:
        description = "Detects Sysinternals tools using hex patterns"
        author = "ChatGPT"
        reference = "https://docs.microsoft.com/en-us/sysinternals"
    strings:
        $hex1 = {53 59 53 49 4E 54 45 52 4E 41 4C 53 20 53 4F 46 54 57 41 52 45 20 4C 49 43 45 4E 53 45 20 54 45 52 4D 53}

    condition:
        any of ($hex*)
}
