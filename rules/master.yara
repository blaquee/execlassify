import "pe"

rule UPXGeneric
{
    meta:
        author = "Kevin Finnigin"
        author_email = "kfinnigin@cylance.com"
        date = "2016-03-28"

    condition:
        for any i in (0..pe.number_of_sections-1):
            (pe.sections[i].name contains "UPX0" and pe.sections[i+1].name contains "UPX1")
}

rule AutoIt
{
    meta:
        author = "Kevin Finnigin"
        author_email = "kfinnigin@cylance.com"
        date = "2016-03-29"
        classification = "PUP"
        subclass = "Scripting Tool"

    strings:
        $a = {A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D}
        $b = "AU3!EA06"

    condition:
        $a and #b == 2 and (@a[1] + 16 == @b[1]) and UPXGeneric
}
rule NSIS
{

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
        author = "Greg Lindor"
        author_email = "glindor@cylance.com"
        date = "2016-04-05"
        classification = "PUP"
        subclass = "Other"

    strings:
        $inno1 = "Inno Setup Setup Data" ascii wide
        $inno2 = "Inno Setup Messages" ascii wide
        $inno3 = "JR.Inno.Setup" wide ascii
    condition:
        (pe.characteristics & pe.EXECUTABLE_IMAGE) and has_manifest and (any of ($inno*))
}