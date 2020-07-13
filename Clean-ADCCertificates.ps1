Function Clean-ADCCertificates {
    <#
    .SYNOPSIS
        Cleanup old/unused certificates on a Citrix ADC.
    .DESCRIPTION
        Remotely cleanup old/unused certificates on a Citrix ADC.
    .PARAMETER ManagementURL
        The URI/URL to connect to, E.g. "https://citrixadc.domain.local".
    .PARAMETER Credential
        The credential to authenticate to the NetScaler with.
    .PARAMETER Backup
        Backup the configuration first (full) before any changes are made.
    .PARAMETER SaveConfig
        Save the configration after all changes are made.
        NOTE: This is selected by default, specify "-SaveConfig:$false" to disable saving the configuration.
    .EXAMPLE
        $Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
        Clean-ADCCertificates -ManagementURL = "https://citrixadc.domain.local" -Credential $Credential
    .EXAMPLE
        # OPTIONAL: You dot-source this file of load the function yourself
        . .\Clean-ADCCertificates.ps1
        #Specify the parameters
        $Params = @{
            ManagementURL = "https://citrixadc.domain.local"
            Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
            Backup = $true
            SaveConfig = $true
        }
        #Run function
        Clean-ADCCertificates @Params
    .NOTES
        File Name : Clean-ADCCertificates.ps1
        Version   : v0.1
        Author    : John Billekens
        Requires  : PowerShell v5.1 and up
                    ADC 11.x and up
    .LINK
        https://blog.j81.nl
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$ManagementURL,

        [parameter(Mandatory)]
        [pscredential]$Credential,
        
        [Switch]$Backup,
        
        [Switch]$SaveConfig = $true
    )

    #requires -version 5.1

    #region Functions
    
    function Invoke-ADCRestApi {
        <#
        .SYNOPSIS
            Invoke ADC NITRO REST API
        .DESCRIPTION
            Invoke ADC NITRO REST API
        .PARAMETER Session
            An existing custom ADC Web Request Session object returned by Connect-ADC
        .PARAMETER Method
            Specifies the method used for the web request
        .PARAMETER Type
            Type of the ADC appliance resource
        .PARAMETER Resource
            Name of the ADC appliance resource, optional
        .PARAMETER Action
            Name of the action to perform on the ADC appliance resource
        .PARAMETER Arguments
            One or more arguments for the web request, in hashtable format
        .PARAMETER Query
            Specifies a query that can be send  in the web request
        .PARAMETER Filters
            Specifies a filter that can be send to the remote server, in hashtable format
        .PARAMETER Payload
            Payload  of the web request, in hashtable format
        .PARAMETER GetWarning
            Switch parameter, when turned on, warning message will be sent in 'message' field and 'WARNING' value is set in severity field of the response in case there is a warning.
            Turned off by default
        .PARAMETER OnErrorAction
            Use this parameter to set the onerror status for nitro request. Applicable only for bulk requests.
            Acceptable values: "EXIT", "CONTINUE", "ROLLBACK", default to "EXIT"
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [PSObject]$Session,
    
            [Parameter(Mandatory = $true)]
            [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
            [string]$Method,
    
            [Parameter(Mandatory = $true)]
            [string]$Type,
    
            [string]$Resource,
    
            [string]$Action,
    
            [hashtable]$Arguments = @{},
            
            [ValidateCount(1,1)]
            [hashtable]$Query = @{},
    
            [switch]$Stat = $false,
    
            [ValidateScript( {$Method -eq 'GET'})]
            [hashtable]$Filters = @{},
    
            [ValidateScript( {$Method -ne 'GET'})]
            [hashtable]$Payload = @{},
    
            [switch]$GetWarning = $false,
    
            [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
            [string]$OnErrorAction = 'EXIT',
            
            [Switch]$Clean
        )
        # https://github.com/devblackops/NetScaler
        if ([string]::IsNullOrEmpty($($Session.ManagementURL))) {
            throw "ERROR. Probably not logged into the ADC"
        }
        if ($Stat) {
            $uri = "$($Session.ManagementURL)/nitro/v1/stat/$Type"
        } else {
            $uri = "$($Session.ManagementURL)/nitro/v1/config/$Type"
        }
        if (-not ([string]::IsNullOrEmpty($Resource))) {
            $uri += "/$Resource"
        }
        if ($Method -ne 'GET') {
            if (-not ([string]::IsNullOrEmpty($Action))) {
                $uri += "?action=$Action"
            }
    
            if ($Arguments.Count -gt 0) {
                $queryPresent = $true
                if ($uri -like '*?action*') {
                    $uri += '&args='
                } else {
                    $uri += '?args='
                }
                $argsList = @()
                foreach ($arg in $Arguments.GetEnumerator()) {
                    $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
                }
                $uri += $argsList -join ','
            }
        } else {
            $queryPresent = $false
            if ($Arguments.Count -gt 0) {
                $queryPresent = $true
                $uri += '?args='
                $argsList = @()
                foreach ($arg in $Arguments.GetEnumerator()) {
                    $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
                }
                $uri += $argsList -join ','
            }
            if ($Filters.Count -gt 0) {
                $uri += if ($queryPresent) { '&filter=' } else { '?filter=' }
                $filterList = @()
                foreach ($filter in $Filters.GetEnumerator()) {
                    $filterList += "$($filter.Name):$([System.Uri]::EscapeDataString($filter.Value))"
                }
                $uri += $filterList -join ','
            }
            if ($Query.Count -gt 0) {
                $uri += $Query.GetEnumerator() | Foreach {"?$($_.Name)=$([System.Uri]::EscapeDataString($_.Value))"}
            }
        }
        Write-Verbose -Message "URI: $uri"
    
        $jsonPayload = $null
        if ($Method -ne 'GET') {
            $warning = if ($GetWarning) { 'YES' } else { 'NO' }
            $hashtablePayload = @{}
            $hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#>}
            $hashtablePayload.$Type = $Payload
            $jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100
            Write-Verbose -Message "JSON Method: $Method | Payload:`n$jsonPayload"
        }
        
        $response = $null
        $restError = $null
        try {
            $restError = @()
            $restParams = @{
                Uri           = $uri
                ContentType   = 'application/json'
                Method        = $Method
                WebSession    = $Session.WebSession
                ErrorVariable = 'restError'
                Verbose       = $false
            }
    
            if ($Method -ne 'GET') {
                $restParams.Add('Body', $jsonPayload)
            }
    
            $response = Invoke-RestMethod @restParams
    
            if ($response) {
                if ($response.severity -eq 'ERROR') {
                    throw "Error. See response: `n$($response | Format-List -Property * | Out-String)"
                } else {
                    Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
                    if ($Method -eq "GET") { 
                        if ($Clean -and (-not ([String]::IsNullOrEmpty($Type)))) {
                            return $response | Select -ExpandProperty $Type -ErrorAction SilentlyContinue
                        } else {
                            return $response 
                        }
                    }
                }
            }
        } catch [Exception] {
            if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
                Write-Verbose -Message 'Connection closed due to reboot'
            } else {
                throw $_
            }
        }
    }
    
    function Connect-ADC {
        <#
        .SYNOPSIS
            Establish a session with Citrix ADC.
        .DESCRIPTION
            Establish a session with Citrix ADC.
        .PARAMETER ManagementURL
            The URI/URL to connect to, E.g. "https://citrixadc.domain.local".
        .PARAMETER Credential
            The credential to authenticate to the ADC with.
        .PARAMETER Timeout
            Timeout in seconds for session object.
        .PARAMETER PassThru
            Return the ADC session object.
        #>
        [cmdletbinding()]
        param(
            [parameter(Mandatory)]
            [string]$ManagementURL,
    
            [parameter(Mandatory)]
            [pscredential]$Credential,
    
            [int]$Timeout = 3600,
    
            [switch]$PassThru
        )
        # Based on https://github.com/devblackops/NetScaler
    
        function Ignore-SSLChecks {
            Write-Verbose "Ignoring SSL checks"
            $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
            $Provider.CreateCompiler() | Out-Null
            $Params = New-Object System.CodeDom.Compiler.CompilerParameters
            $Params.GenerateExecutable = $false
            $Params.GenerateInMemory = $true
            $Params.IncludeDebugInformation = $false
            $Params.ReferencedAssemblies.Add("System.DLL") > $null
            $TASource=@'
                namespace Local.ToolkitExtensions.Net.CertificatePolicy
                {
                    public class TrustAll : System.Net.ICertificatePolicy
                    {
                        public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                        {
                            return true;
                        }
                    }
                }
'@ 
            $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
            $TAAssembly=$TAResults.CompiledAssembly
            $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
            [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
            [System.Net.ServicePointManager]::SecurityProtocol = 
                [System.Net.SecurityProtocolType]::Tls13 -bor `
                [System.Net.SecurityProtocolType]::Tls12 -bor `
                [System.Net.SecurityProtocolType]::Tls11
        }
        Write-Verbose -Message "Connecting to $ManagementURL..."
        if ($ManagementURL -like "https://*") {
            Write-Verbose "Connection is SSL"
            Ignore-SSLChecks
        }
        try {
            $login = @{
                login = @{
                    username = $Credential.UserName;
                    password = $Credential.GetNetworkCredential().Password
                    timeout  = $Timeout
                }
            }
            $loginJson = ConvertTo-Json -InputObject $login
            $saveSession = @{}
            $params = @{
                Uri             = "$ManagementURL/nitro/v1/config/login"
                Method          = 'POST'
                Body            = $loginJson
                SessionVariable = 'saveSession'
                ContentType     = 'application/json'
                ErrorVariable   = 'restError'
                Verbose         = $false
            }
            $response = Invoke-RestMethod @params
    
            if ($response.severity -eq 'ERROR') {
                throw "Error. See response: `n$($response | Format-List -Property * | Out-String)"
            } else {
                Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
            }
        } catch [Exception] {
            throw $_
        }
        $session = [PSObject]@{
            ManagementURL = [string]$ManagementURL;
            WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
            Username      = $Credential.UserName;
            Version       = "UNKNOWN";
        }
    
        try {
            Write-Verbose -Message "Trying to retreive the ADC version"
            $params = @{
                Uri           = "$ManagementURL/nitro/v1/config/nsversion"
                Method        = 'GET'
                WebSession    = $Session.WebSession
                ContentType   = 'application/json'
                ErrorVariable = 'restError'
                Verbose       = $false
            }
            $response = Invoke-RestMethod @params
            Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
            $version = $response.nsversion.version.Split(",")[0]
            if (-not ([string]::IsNullOrWhiteSpace($version))) {
                $session.version = $version
            }
        } catch {
            Write-Verbose -Message "Error. See response: `n$($response | Format-List -Property * | Out-String)"
        }
        $Script:NSSession = $session
        
        if ($PassThru) {
            return $session
        }
    }
    
    function Get-ADCCertificateRemoveInfo {
        [cmdletbinding()]
        param(
            [hashtable]$Session,
            
            [String[]]$ExcludedCertKey= @()
        )
    
        $InstalledCertificates = Invoke-ADCRestApi -Session $Session -Method GET -Type sslcertkey -Clean | Where-Object {$_.certkey -notmatch '^ns-server-certificate$'} | Select certkey,status,linkcertkeyname,serial,@{label="cert";expression={"$($_.cert.Replace('/nsconfig/ssl/',''))"}},@{label="key";expression={"$($_.key.Replace('/nsconfig/ssl/',''))"}}
        
        $Arguments = @{"filelocation" = "/nsconfig/ssl"; }
        $CertificateFiles = Invoke-ADCRestApi -Session $Session -Method Get -Type systemfile -Arguments $Arguments -Clean | Where-Object {$_.filename -notmatch '^ns-root.*$|^ns-server.*$|^ns-sftrust.*$'}
        
        $Query = @{"bulkbindings" = "yes"; }
        $CertificateBindings = Invoke-ADCRestApi -Session $Session -Method Get -Type sslcertkey_binding -Query $Query -Clean
        
        $LinkedCertificate = Invoke-ADCRestApi -Session $Session -Method Get -Type sslcertlink -Clean
        
        $Certificates = @()
        Foreach ($cert in $CertificateFiles) {
            $Removable = $true
            $certData = $InstalledCertificates | Where-Object { $_.cert -match "^$($cert.filename)$|^.*/$($cert.filename)$" }
            $keyData = $InstalledCertificates | Where-Object { $_.key -match "^$($cert.filename)$|^.*/$($cert.filename)$" }
            $CertFileData = @()
            Foreach ($item in $certData) {
                $Linked = $LinkedCertificate | Where-Object {$_.linkcertkeyname -eq $item.certkey} | Select -ExpandProperty certkeyname
                
                
                if ((($CertificateBindings | Where-Object {$_.certkey -eq $item.certkey} | Get-Member -MemberType NoteProperty | Where-Object Name -like "*binding").Name) -or ($Linked)) {
                    $CertFileData += $certData | Select *,@{label="bound";expression={$true}},@{label="linkedcertkey";expression={$Linked}}
                    $Removable = $false
                } else {
                    $CertFileData += $certData | Select *,@{label="bound";expression={$false}},@{label="linkedcertkey";expression={$Linked}}
                }
            }
            $KeyFileData = @()
            Foreach ($item in $keyData) {
                $Linked = $InstalledCertificates | Where {$_.linkcertkeyname -eq $item.certkey -and $null -ne $_.linkcertkeyname} | Select -ExpandProperty certkey
                if ((($CertificateBindings | Where-Object {$_.certkey -eq $item.certkey} | Get-Member -MemberType NoteProperty | Where-Object Name -like "*binding").Name) -or ($Linked)) {
                    $KeyFileData += $keyData | Select *,@{label="bound";expression={$true}},@{label="linkedcertkey";expression={$Linked}}
                    $Removable = $false
                } else {
                    $KeyFileData += $keyData | Select *,@{label="bound";expression={$false}},@{label="linkedcertkey";expression={$Linked}}
                }
            }
            $Certificates += [PsCustomObject]@{
                filename = $cert.filename
                filelocation = $cert.filelocation
                certData = $CertFileData
                keyData = $KeyFileData
                removable = $Removable
            }
        }
        return $Certificates
    }
    
    function Delete-ADCCertKey {
        [cmdletbinding()]
        param(
            [hashtable]$Session,
            
            [String]$CertKey,
            
            [Switch]$Text
        )
        try {
            $response = Invoke-ADCRestApi -Session $Session -Method DELETE -Type sslcertkey -Resource $CertKey
            if ($Text) {Write-Host -ForeGroundColor Green "Removed" }
        } catch {
            if ($Text) {Write-Host -ForeGroundColor Yellow "NOT removed" }
            $response = $null
        }
        if (-Not $Text) {
            return $response
        }
    }
    
    function Delete-ADCSystemFile {
        [cmdletbinding()]
        param(
            [hashtable]$Session,
            
            [String]$FileName,
            
            [String]$FileLocation,
            
            [Switch]$Text
        )
        try {
            $Arguments = @{"filelocation" = "$FileLocation"; }
            $response = Invoke-ADCRestApi -Session $Session -Method DELETE -Type systemfile -Resource $FileName -Arguments $Arguments
            if ($Text) {Write-Host -ForeGroundColor Green "Removed" }
        } catch {
            $response = $null
            if ($Text) {Write-Host -ForeGroundColor Yellow "NOT removed" }
        }
        return $response
    }
    
    function Save-ADCConfig {
        [cmdletbinding()]
        param(
            [hashtable]$Session,
            
            [Switch]$Text
        )
        try {
            $response = Invoke-ADCRestApi -Session $Session -Method POST -Type nsconfig -Action save
            if ($Text) {Write-Host -ForeGroundColor Green "Saved" }
        } catch {
            $response = $null
            if ($Text) {Write-Host -ForeGroundColor Yellow "NOT Saved" }
        }
        return $response
    }
    
    function Backup-ADCConfig {
        [cmdletbinding()]
        param(
            [hashtable]$Session,
            
            [String]$Name = "ADCBackup_$((Get-Date).ToString("yyyyMMdd_HHmm"))",
    
            [String]$Comment = "Backup created by PoSH function Backup-ADCConfig",
            
            [ValidateSet("full", "basic")]
            [String]$Level="full",
            
            [alias("SaveConfig")]
            [Switch]$SaveConfigFirst,
            
            [Switch]$Text
        )
        if ($SaveConfigFirst) {
            Write-Verbose "SaveConfig parameter specified, saving config"
            Save-ADCConfig -Session $Session | Out-Null
        }
        try {
            $payload = @{"filename"="$Name"; "level"="$($Level.ToLower())"; "comment"="$Comment"}
            $response = Invoke-ADCRestApi -Session $NSSession -Method POST -Type systembackup -Payload $payload -Action create
            if ($Text) {Write-Host -ForeGroundColor Green "Back-upped [$Name]" }
        } catch {
            $response = $null
            if ($Text) {Write-Host -ForeGroundColor Red "NOT Back-upped" }
        }
        return $response
    }

    #endregion Functions
    
    Write-Verbose "Trying to login into the Citrix ADC."
    Write-Host -ForeGroundColor White "`r`nADC Info"
    $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
    Write-Host -ForeGroundColor White -NoNewLine " -URL........: "
    Write-Host -ForeGroundColor Cyan "$ManagementURL"
    Write-Host -ForeGroundColor White -NoNewLine " -Username...: "
    Write-Host -ForeGroundColor Cyan "$($ADCSession.Username)"
    Write-Host -ForeGroundColor White -NoNewLine " -Password...: "
    Write-Host -ForeGroundColor Cyan "**********"
    Write-Host -ForeGroundColor White -NoNewLine " -Version....: "
    Write-Host -ForeGroundColor Cyan "$($ADCSession.Version)"
    $NSVersion = [double]$($ADCSession.version.split(" ")[1].Replace("NS", "").Replace(":", ""))
    if ($NSVersion -lt 11) {
        Write-Warning "Only ADC version 11 and up is supported"
        Exit(1)
    }
    
    if ($Backup) {
        Write-Host -NoNewLine "`r`nBacking up the configuration: "
        Backup-ADCConfig -Session $ADCSession -Name "CleanCerts_$((Get-Date).ToString("yyyyMMdd_HHmm"))" -Comment "Backup created by PoSH function Clean-ADCCertificates" -SaveConfigFirst -Text
    }
    try {
        Write-Verbose "Retrieving the certificate details."    
        $Certs = Get-ADCCertificateRemoveInfo -Session $ADCSession
        $RemovableCerts = $Certs | Where {$_.removable -eq $true}
        if ($RemovableCerts.Count -gt 0) {
            Write-Host "`r`nRemoving CertKeys from the configuration for unused certificates"
            Foreach ($RemovableCert in $RemovableCerts) {
            
                $RemovableCert | Where-Object {$_.certData.bound -eq $false} | Foreach {
                    Write-Host " CertKey.....: $($_.certData.certkey)"
                    Write-Host -NoNewLine " -Result.....: "
                    $result = Delete-ADCCertKey -Session $ADCSession -CertKey $_.certData.certkey -Text
                }
                if ($_.keyData.certkey -ne $_.certData.certkey) {
                    $RemovableCert | Where-Object {$_.keyData.bound -eq $false} | Foreach {
                        Write-Host " CertKey.....: $($_.keyData.certkey)"
                        Write-Host -NoNewLine " -Result.....: "
                        $result = Delete-ADCCertKey -Session $ADCSession -CertKey $_.keyData.certkey -Text
                    }
                }
            }
        
            Write-Verbose "Retrieving certificates and remove unbound files"
            $Certs = Get-ADCCertificateRemoveInfo -Session $ADCSession
            Write-Host -ForeGroundColor Green "`r`nDone`r`n"
        }
        $RemovableCerts = $Certs | Where-Object {($_.removable -eq $true) -and ($_.certData.count -eq 0) -and ($_.keyData.count -eq 0)}
        if ($RemovableCerts.Count -gt 0) {
            Write-Host -ForeGroundColor White "Removing certificate files"
            $RemovableCerts | Foreach {
                Write-Host " Filename....: $($_.fileName)"
                Write-Host -NoNewLine " -Result.....: "
                $result = Delete-ADCSystemFile -Session $ADCSession -FileName $_.fileName -FileLocation $_.filelocation -Text
            }
            Write-Verbose "Retrieving final result to check for expired certificates"
            $Certs = Get-ADCCertificateRemoveInfo -Session $ADCSession
            Write-Host -ForeGroundColor Green "`r`nDone`r`n"
        } else {
            Write-Host "`r`nNothing to remove, the location `"/nsconfig/ssl/`" is tidy!`r`n"
        }
        
        if ($($Certs | Where-Object {$_.certData.status -eq "Expired"}).count -gt 0) {
            Write-Warning "You still have EXPIRED certificates bound/active in the configuration!"
        }
        
        if ($SaveConfig) {
            Write-Host -NoNewLine "Saving the config: "
            $result = Save-ADCConfig -Session $ADCSession -Text
        }
        Write-Host -ForeGroundColor Green "`r`nFinished!`r`n"
    } catch {
        Write-Host -ForeGroundColor Red "Caught an error. Exception Message: $($_.Exception.Message)"
    }
}

<#   

#Specify the parameters
$Params = @{
    ManagementURL = "https://citrixadc.domain.local"
    Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
    Backup = $true
    SaveConfig = $true
}

#Run function
Clean-ADCCertificates @Params

#>
