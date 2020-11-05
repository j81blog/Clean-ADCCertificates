$text = @"

#Load functions

. .\adcfunctions.ps1

#Specify the parameters

`$Params = @{
    ManagementURL = "https://citrixadc.domain.local"
    Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
    Backup = `$true
}

#Run function
Invoke-CleanADCCertificates @Params

"@

Write-Host $text