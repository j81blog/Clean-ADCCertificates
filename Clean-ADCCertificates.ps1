""
Write-Host -ForeGroundColor Yellow "`r`n#> Load functions"
Write-Host -ForeGroundColor White ". .\adcfunctions.ps1"
Write-Host -ForeGroundColor Yellow "`r`n#> Specify the parameters"
Write-Host -ForeGroundColor White @'
$Params = @{
    ManagementURL = "https://citrixadc.domain.local"
    Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
    Backup = $true
}
'@
Write-Host -ForeGroundColor Yellow "`r`n#> Run function"
Write-Host -ForeGroundColor White "Invoke-CleanADCCertificates @Params"
""
