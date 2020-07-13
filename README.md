# Clean-ADCCertificates
Remotely cleanup old/unused certificates on a Citrix ADC.

```PowerShell
$Params = @{
    ManagementURL = "https://citrixadc.domain.local"
    Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
    Backup = $true
    SaveConfig = $true
}

Clean-ADCCertificates @Params
```
