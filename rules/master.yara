import "pe"

rule nullsoft
{
    strings:
        $nullsoft = "NullSoftInst2" ascii fullword
    condition:
    
}