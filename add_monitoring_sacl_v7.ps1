# ---------------------------------------
# PARAM SET
# ---------------------------------------

# ---------------------------------------
# DistinguishedName
# a fournir par le user
if (-not $args[0]) {
    throw "Error: argument (`$args[0]`) est obligatoire. il s'agit du DistinguishedName"
}
$objectDN = $args[0]

# ---------------------------------------
# AuditRights
# default = ReadProperty
# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-10.0
if ($args.Count -ge 2 -and $args[1]) {
    $AuditRights = $args[1]
} else {
    $AuditRights = "ReadProperty"
}

# ---------------------------------------
# Guid / properties
# default = Empty
# Exemple, description servicePrincipalName"
if ($args.Count -ge 3 -and $args[2]) {
    $properties = $args[2]
	$root = [ADSI]"LDAP://RootDSE"
	$schemaNC = $root.schemaNamingContext

	$attr = [ADSI]"LDAP://CN=$properties,$schemaNC"
	$guid = New-Object Guid ($attr.schemaIDGUID)
} else {
	$properties="All"
    $guid = [Guid]::Empty
}

# ---------------------------------------
# Inheritance
# default = None
# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-10.0
if ($args.Count -ge 4 -and $args[3]) {
    $Inheritance = $args[3]
} else {
    $Inheritance = "None"
}

# ---------------------------------------
# APPLY CHANGE
# ---------------------------------------

# Chargement des assemblies
Add-Type -AssemblyName System.DirectoryServices.Protocols

# Setup LDAP server
$ldapServer = "essos.local"

# Connexion LDAP
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapServer)
$ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
$request = New-Object System.DirectoryServices.Protocols.SearchRequest($objectDN, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, @("nTSecurityDescriptor"))
$response = $ldap.SendRequest($request)

# Récupération du ntSecurityDescriptor (byte[])
$sdBytes = $response.Entries[0].Attributes["nTSecurityDescriptor"][0]

# Création d'un ActiveDirectorySecurity à partir des bytes
$sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
$sd.SetSecurityDescriptorBinaryForm($sdBytes, [System.Security.AccessControl.AccessControlSections]::Audit)

# Création du SID Everyone
$everyoneSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

# Création d'une règle d'audit ReadProperty Success
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyoneSid,
    [System.DirectoryServices.ActiveDirectoryRights]::$AuditRights,
    [System.Security.AccessControl.AuditFlags]::Success,
    $guid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::$Inheritance,
    [Guid]::Empty
)

# Ajout de la règle d'audit
$sd.AddAuditRule($rule)

# Récupérer le binaire du nouveau SD
$newSDBytes = $sd.GetSecurityDescriptorBinaryForm()

# Modifier l'attribut nTSecurityDescriptor
$modRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($objectDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, "nTSecurityDescriptor", $newSDBytes)

# Envoi de la modification
$response = $ldap.SendRequest($modRequest)

# Affichage du résultat
$output_data="AuditRights:'$AuditRights', Inheritance:'$Inheritance', Properties:'$properties', Guid:'$guid' into objectDN:'$objectDN'"
if ($response.ResultCode -eq 0) {
	Write-Host "[+] add $output_data"
} else {
	Write-Host "[-] fail $output_data"
}