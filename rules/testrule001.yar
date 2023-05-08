rule testrule_001
{
    meta:
        description = "Detects test pattern"
        author = "mbilal"
        reference = ""
    strings:
        $str1 = "@googlemail.com"
	  $str2 = "mimikatz.exe"

    condition:
        any of ($str*)
}
