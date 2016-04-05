import "pe"

rule nullsoft
{
    strings:
        $nullsoft = "NullSoftInst2" ascii
    condition:
        (pe.characteristics & pe.EXECUTABLE_IMAGE) and $nullsoft
}

rule has_manifest
{
    condition:
    for any i in (0..pe.number_of_resources-1): 
        (pe.resources[i].type == pe.RESOURCE_TYPE_MANIFEST)
}

rule Inno
{
    strings:
        $inno1 = "Inno Setup Setup Data" ascii
        $inno2 = "Inno Setup Messages" ascii
        $inno3 = "JR.Inno.Setup" wide ascii
    condition:
        (pe.characteristics & pe.EXECUTABLE_IMAGE) and has_manifest and (any of ($inno*))
}