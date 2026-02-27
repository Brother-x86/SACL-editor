# utilisation

- param1 : distinguishedName , target for the SACL
- param2 (optionnal): *AuditRights* , default=`ReadProperty`  https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-10.0
- param3 (optionnal): *Guid / properties* , default=`[Guid]::Empty` : apply into all properties
- param4 (optionnal): *Inheritance*, default=`None`  : no Inheritance https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-10.0

# exemple


## without args : ReadProperty into all properties

Par défaut, sans argument, ReadProperty sur un object unique

```
powershell .\add_monitoring_sacl_v7.ps1 'CN=missandei,CN=Users,DC=essos,DC=local' 
```

## ReadProperty into description

``````
powershell .\add_monitoring_sacl_v7.ps1 'CN=Users,DC=essos,DC=local' ReadProperty description
``````

## WriteProperty into Service-Principal-Name with Inheritance=Descendents

Be carrefull, servicePrincipalName is Service-Principal-Name

``````
powershell .\add_monitoring_sacl_v7.ps1 'CN=Computers,DC=essos,DC=local' WriteProperty Service-Principal-Name Descendents
``````

## WriteProperty into msDS-KeyCredentialLink with Inheritance=Descendents

idem, msDS-KeyCredentialLink is ms-DS-Key-Credential-Link

``````
powershell .\add_monitoring_sacl_v7.ps1 'CN=Computers,DC=essos,DC=local' WriteProperty ms-DS-Key-Credential-Link Descendents
``````

## WriteProperty into ms-DS-Allowed-To-Delegate-To with Inheritance=Descendents

``````
powershell .\add_monitoring_sacl_v7.ps1 'CN=Computers,DC=essos,DC=local' WriteProperty ms-DS-Key-Credential-Link Descendents
``````

# Disclaimer

A ne pas utiliser sur la racine, cela casse le domaine, ici `DC=essos,DC=local`
Il y a un bug non identifié.