import "pe"

rule NSIS {

  meta:
    author = "Brad Arndt"
    author_email = "barndt@cylance.com"
    date = "2016-04-05"
    classification = "PUP"
    subclass = "Other"
    
  strings:
    $a = "NullsoftInst" wide ascii
    $b = "NSIS Error" wide ascii
    $c = "nsis.sf.net" wide ascii
    $d = "Nullsoft.NSIS.exehead" wide ascii
    $e = "Error launching installer" wide ascii
    $f = "Installer integrity check has failed. Common causes include" wide ascii
    
  condition:
    (pe.characteristics & pe.EXECUTABLE_IMAGE) and 5 of them
}

rule has_manifest
{
    condition:
    for any i in (0..pe.number_of_resources-1): 
        (pe.resources[i].type == pe.RESOURCE_TYPE_MANIFEST)
}

rule Inno
{
    meta:
        
    strings:
        $inno1 = "Inno Setup Setup Data" ascii
        $inno2 = "Inno Setup Messages" ascii
        $inno3 = "JR.Inno.Setup" wide ascii
    condition:
        (pe.characteristics & pe.EXECUTABLE_IMAGE) and has_manifest and (any of ($inno*))
}