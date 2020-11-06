# Invoke-CleanADCCertificates
Remotely cleanup old/unused certificates on a Citrix ADC.

**Load functions**
```PowerShell
. .\adcfunctions.ps1
```

**Specify the parameters**
```PowerShell
$Params = @{
    ManagementURL = "https://citrixadc.domain.local"
    Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
    Backup = $true
}
```

**Run function**
```PowerShell
Invoke-CleanADCCertificates @Params
```
