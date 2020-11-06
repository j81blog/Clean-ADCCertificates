# Invoke-CleanADCCertificates
Remotely cleanup old/unused certificates on a Citrix ADC.

```PowerShell
**Load functions**
. .\adcfunctions.ps1

**Specify the parameters**
$Params = @{
    ManagementURL = "https://citrixadc.domain.local"
    Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
    Backup = $true
}

**Run function**
Invoke-CleanADCCertificates @Params
```
