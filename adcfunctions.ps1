function Invoke-CleanADCCertificates {
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
    .PARAMETER noSaveConfig
        The configuration will be saved by default after all changes are made.
        Specify "-NoSaveConfig" to disable saving the configuration.
    .EXAMPLE
        $Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
        Invoke-CleanADCCertificates -ManagementURL = "https://citrixadc.domain.local" -Credential $Credential
    .EXAMPLE
        # OPTIONAL: You dot-source this file of load the function yourself
        . .\Invoke-CleanADCCertificates.ps1
        #Specify the parameters
        $Params = @{
            ManagementURL = "https://citrixadc.domain.local"
            Credential = Get-Credential -UserName "nsroot" -Message "Citrix ADC account"
            Backup = $true
            SaveConfig = $true
        }
        #Run function
        Invoke-CleanADCCertificates @Params
    .NOTES
        File Name : Invoke-CleanADCCertificates.ps1
        Version   : v0.2
        Author    : John Billekens
        Requires  : PowerShell v5.1 and up
                    ADC 11.x and up
    .LINK
        https://blog.j81.nl
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [System.Uri]$ManagementURL,

        [parameter(Mandatory)]
        [pscredential]$Credential,
        
        [Switch]$Backup,
        
        [Switch]$NoSaveConfig,
        
        [Int]$Attempts = 2        
    )

    #requires -version 5.1

    #region functions
    
    function Get-ADCCertificateRemoveInfo {
        [cmdletbinding()]
        param(
            [hashtable]$Session = (Invoke-CheckADCSession),
            
            [String[]]$ExcludedCertKey = @()
        )
    
        $InstalledCertificates = Invoke-GetADCSSLCertKey -ADCSession $Session | Expand-ADCResult | Where-Object { $_.certkey -notmatch '^ns-server-certificate$' } | Select-Object certkey, status, linkcertkeyname, serial, @{label = "cert"; expression = { "$($_.cert.Replace('/nsconfig/ssl/',''))" } }, @{label = "key"; expression = { "$($_.key.Replace('/nsconfig/ssl/',''))" } }
        
        $SSLFileLocation = "/nsconfig/ssl"
        $FileLocations = Invoke-GetADCSystemFileDirectories -FileLocation $SSLFileLocation
        $CertificateFiles = $FileLocations | ForEach-Object { Invoke-GetADCSystemFile -FileLocation $_ -ADCSession $Session | Expand-ADCResult | Where-Object { ($_.filename -notmatch '^ns-root.*$|^ns-server.*$|^ns-sftrust.*$') -And ($_.filemode -ne "DIRECTORY") } }
        
        $CertificateBindings = Invoke-GetADCSSLCertKeyBinding -ADCSession $Session | Expand-ADCResult
        
        $LinkedCertificate = Invoke-GetADCSSLCertLink -ADCSession $Session | Expand-ADCResult
        
        $Certificates = @()
        Foreach ($cert in $CertificateFiles) {
            $Removable = $true
            $certData = $InstalledCertificates | Where-Object { $_.cert -match "^$($cert.filename)$|^.*/$($cert.filename)$" }
            $keyData = $InstalledCertificates | Where-Object { $_.key -match "^$($cert.filename)$|^.*/$($cert.filename)$" }
            $CertFileData = @()
            Foreach ($item in $certData) {
                $Linked = $LinkedCertificate | Where-Object { $_.linkcertkeyname -eq $item.certkey } | Select-Object -ExpandProperty certkeyname
                
                
                if ((($CertificateBindings | Where-Object { $_.certkey -eq $item.certkey } | Get-Member -MemberType NoteProperty | Where-Object Name -like "*binding").Name) -or ($Linked)) {
                    $CertFileData += $certData | Select-Object *, @{label = "bound"; expression = { $true } }, @{label = "linkedcertkey"; expression = { $Linked } }
                    $Removable = $false
                } else {
                    $CertFileData += $certData | Select-Object *, @{label = "bound"; expression = { $false } }, @{label = "linkedcertkey"; expression = { $Linked } }
                }
            }
            $KeyFileData = @()
            Foreach ($item in $keyData) {
                $Linked = $InstalledCertificates | Where-Object { $_.linkcertkeyname -eq $item.certkey -and $null -ne $_.linkcertkeyname } | Select-Object -ExpandProperty certkey
                if ((($CertificateBindings | Where-Object { $_.certkey -eq $item.certkey } | Get-Member -MemberType NoteProperty | Where-Object Name -like "*binding").Name) -or ($Linked)) {
                    $KeyFileData += $keyData | Select-Object *, @{label = "bound"; expression = { $true } }, @{label = "linkedcertkey"; expression = { $Linked } }
                    $Removable = $false
                } else {
                    $KeyFileData += $keyData | Select-Object *, @{label = "bound"; expression = { $false } }, @{label = "linkedcertkey"; expression = { $Linked } }
                }
            }
            $Certificates += [PsCustomObject]@{
                filename     = $cert.filename
                filelocation = $cert.filelocation
                certData     = $CertFileData
                keyData      = $KeyFileData
                removable    = $Removable
            }
        }
        return $Certificates
    }
    
    #endregion functions

    Write-Verbose "Trying to login into the Citrix ADC."
    Write-Host -ForeGroundColor White "`r`nADC Connection"
    Write-Host -ForeGroundColor White -NoNewLine " -Connecting............: "
    try {
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru -ErrorAction Stop
        $IsConnected = $true
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        $HANode = Invoke-GetADCHANode | Expand-ADCResult
        $nsconfig = Invoke-GetADCNSConfig | Expand-ADCResult
        if ($nsconfig.ipaddress -ne $nsconfig.primaryip) {
            Write-Warning "You are connected to a secondary node (Primary node is $($nsconfig.primaryip))"
        }
        $NodeState = $nsconfig.systemtype
        $ADCSessions = @()
        if ($NodeState -like "Stand-alone") {
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            try {
                $PrimaryURL = [System.URI]"$($ManagementURL.Scheme):\\$($nsconfig.ipaddress)"
                $PriSession = Connect-ADC -ManagementURL $PrimaryURL -Credential $Credential -PassThru -ErrorAction Stop
                $PriNode = $HANode | Where-Object { $_.ipaddress -eq $nsconfig.ipaddress }
            } catch {
                $PriSession = $ADCSession
            }
            $ADCSessions += [PsCustomObject]@{ ID = 0; State = "Primary"; Session = $PriSession }
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        } elseif ($NodeState -like "HA") {
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            try {
                $PriNode = $HANode | Where-Object { $_.state -like "Primary" }
                $PrimaryIP = $PriNode.ipaddress
                $PrimaryURL = [System.URI]"$($ManagementURL.Scheme):\\$PrimaryIP"
                $PriSession = Connect-ADC -ManagementURL $PrimaryURL -Credential $Credential -PassThru -ErrorAction Stop
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            } catch {
                Write-Verbose "Error, $($_.Exception.Message)"
                $PriSession = $ADCSession
            }
            $ADCSessions += [PsCustomObject]@{ ID = 0; State = "Primary  "; Session = $PriSession }
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            try {
                $SecNode = $HANode | Where-Object { $_.state -like "Secondary" }
                if ([String]::IsNullOrEmpty($SecNode)) {
                    $SecNode = $HANode | Where-Object { $_.ipaddress -ne $PriNode.ipaddress }
                }
                $SecondaryIP = $SecNode.ipaddress
                $SecondaryURL = [System.URI]"$($ManagementURL.Scheme):\\$SecondaryIP"
                $SecSession = Connect-ADC -ManagementURL $SecondaryURL -Credential $Credential -PassThru -ErrorAction Stop
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                $ADCSessions += [PsCustomObject]@{ ID = 1; State = "Secondary"; Session = $SecSession }
            } catch {
                Write-Verbose "Error, $($_.Exception.Message)"
                $SecSession = $null
            }
        }
        Write-Host -ForeGroundColor Green " Connected"
    } catch {
        Write-Verbose "Caught an error: $_.Exception.Message"
        Write-Host -ForeGroundColor Red "  ERROR, Could not connect`r`n"
        $IsConnected = $false
    }
    if ($IsConnected) {
        Write-Host -ForeGroundColor White "`r`nADC Info"
        Write-Host -ForeGroundColor White -NoNewLine " -Username..............: "
        Write-Host -ForeGroundColor Cyan "$($ADCSession.Username)"
        Write-Host -ForeGroundColor White -NoNewLine " -Password..............: "
        Write-Host -ForeGroundColor Cyan "**********"
        Write-Host -ForeGroundColor White -NoNewLine " -Configuration.........: "
        Write-Host -ForeGroundColor Cyan "$NodeState"
        Write-Host -ForeGroundColor White -NoNewLine " -Node..................: "
        Write-Host -ForeGroundColor Cyan "$($PriNode.state)"
        Write-Host -ForeGroundColor White -NoNewLine " -URL...................: "
        Write-Host -ForeGroundColor Cyan "$($PrimaryURL.OriginalString)"
        Write-Host -ForeGroundColor White -NoNewLine " -Version...............: "
        Write-Host -ForeGroundColor Cyan "$($PriSession.Version)"
        if ((-Not [String]::IsNullOrEmpty($SecSession)) -Or ($SecNode.state -eq "UNKNOWN")) {
            Write-Host -ForeGroundColor White -NoNewLine " -Node..................: "
            Write-Host -ForeGroundColor Cyan "$($SecNode.state)"
            Write-Host -ForeGroundColor White -NoNewLine " -URL...................: "
            Write-Host -ForeGroundColor Cyan "$($SecondaryURL.OriginalString)"
            Write-Host -ForeGroundColor White -NoNewLine " -Version...............: "
            Write-Host -ForeGroundColor Cyan "$($SecSession.Version)"
        }
        if ($($ADCSession | ConvertFrom-ADCVersion) -lt [System.Version]"11.0") {
            Write-Warning "Only ADC version 11 and up is supported"
            Exit (1)
        }

        Write-Host -ForeGroundColor White -NoNewLine " -Backup................: "
        if ($Backup) {
            Write-Host -ForeGroundColor Cyan "Initiated"
            Write-Host -ForeGroundColor White -NoNewLine " -Backup Status.........: "
            try {        
                $BackupName = "CleanCerts_$((Get-Date).ToString("yyyyMMdd_HHmm"))"
                $Response = Invoke-BackupADCConfig -Session $PriSession -Name $BackupName -Comment "Backup created by PoSH function Invoke-CleanADCCertificates" -SaveConfigFirst -ErrorAction Stop
                Write-Host -ForeGroundColor Green "OK [$BackupName]"
            } catch {
                Write-Host -ForeGroundColor Red "Failed $($Response.message)"
            }
        } else {
            Write-Host -ForeGroundColor Yellow "Skipped, not configured"
        }
        $loop = 1
        try {
            Write-Verbose "Retrieving the certificate details."
            Do {
                $Certs = Get-ADCCertificateRemoveInfo -Session $PriSession
                $RemovableCerts = $Certs | Where-Object { $_.removable -eq $true }
                if ($RemovableCerts.Count -gt 0) {
                    Write-Host "`r`nRemoving CertKeys from the configuration for unused certificates, attempt $loop/$Attempts"
                    Foreach ($RemovableCert in $RemovableCerts) {
                
                        $RemovableCert | Where-Object { $_.certData.bound -eq $false } | ForEach-Object {
                            Write-Host " CertKey................: $($_.certData.certkey)"
                            Write-Host -NoNewLine " -Removing..............: "
                            $result = Invoke-DeleteADCCertKey -Session $PriSession -CertKey $_.certData.certkey -ErrorAction SilentlyContinue | Write-ADCText
                            Write-Verbose "Result: $result"
                        }
                        if ($_.keyData.certkey -ne $_.certData.certkey) {
                            $RemovableCert | Where-Object { $_.keyData.bound -eq $false } | ForEach-Object {
                                Write-Host " CertKey................: $($_.keyData.certkey)"
                                Write-Host -NoNewLine " -Removing..............: "
                                $result = Invoke-DeleteADCCertKey -Session $PriSession -CertKey $_.keyData.certkey -ErrorAction  SilentlyContinue | Write-ADCText
                                Write-Verbose "Result: $result"
                            }
                        }
                    }
            
                    Write-Verbose "Retrieving certificates and remove unbound files"
                    $Certs = Get-ADCCertificateRemoveInfo -Session $PriSession
                }
                $loop++
            } While ($loop -lt ($Attempts + 1) )
            $RemovableCerts = $Certs | Where-Object { ($_.removable -eq $true) -and ($_.certData.count -eq 0) -and ($_.keyData.count -eq 0) }
            if ($RemovableCerts.Count -gt 0) {
                Write-Host -ForeGroundColor White "`r`nRemoving certificate files"
                $RemovableCerts | ForEach-Object {
                    Write-Host " Filename...............: $($_.filelocation)/$($_.fileName)"
                    foreach ($Session in $ADCSessions) {
                        Write-Host -NoNewLine " -Deleting..............: "
                        Write-Host -NoNewLine -ForeGroundColor Cyan "[$($Session.State)] "
                        $result = Invoke-DeleteADCSystemFile -Session $Session.Session -FileName $_.fileName -FileLocation $_.filelocation | Write-ADCText
                        Write-Verbose "Result: $result"
                    }
                }
            } else {
                Write-Host "`r`nNothing to remove (anymore), the location `"/nsconfig/ssl/`" is tidy!`r`n"
                Break
            }
        
            if ($($Certs | Where-Object { $_.certData.status -eq "Expired" }).count -gt 0) {
                Write-Warning "You still have EXPIRED certificates bound/active in the configuration!"
            }
        
            if (-Not $NoSaveConfig) {
                Write-Host -NoNewLine "Saving the config: "
                try {
                    $result = Invoke-SaveADCConfig -Session $ADCSession -ErrorAction Stop
                    Write-Host -ForeGroundColor Green "Done"
                } catch {
                    Write-Host -ForeGroundColor Red "Failed"
                }
            }
        
        
            Write-Host -ForeGroundColor Green "`r`nFinished!`r`n"
        } catch {
            Write-Host -ForeGroundColor Red "Caught an error. Exception Message: $($_.Exception.Message)"
        }
    }
}

#REST API
#HTTP Status Code on Success: 200 OK
#HTTP Status Code on Failure: 4xx <string> (for general HTTP errors) or 5xx <string> (for Citrix-ADC-specific errors). The response payload provides details of the error.

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
        [Parameter(Mandatory = $true)]
        [System.Uri]$ManagementURL,
    
        [Parameter(Mandatory = $true)]
        [pscredential]$Credential,
    
        [int]$Timeout = 3600,
    
        [switch]$PassThru
    )
    # Based on https://github.com/devblackops/NetScaler
    
    function Set-IgnoreTLSSettings {
        Write-Verbose "Ignoring SSL checks"
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Provider.CreateCompiler() | Out-Null
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource = @'
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
        $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
        $TAAssembly = $TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
        [System.Net.ServicePointManager]::SecurityProtocol = 
        [System.Net.SecurityProtocolType]::Tls13 -bor `
            [System.Net.SecurityProtocolType]::Tls12 -bor `
            [System.Net.SecurityProtocolType]::Tls11
    }
    Write-Verbose -Message "Connecting to $ManagementURL..."
    if ($ManagementURL.scheme -eq "https") {
        Write-Verbose "Connection is SSL"
        Set-IgnoreTLSSettings
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
        $saveSession = @{ }
        $params = @{
            Uri             = "$($ManagementURL.AbsoluteUri)nitro/v1/config/login"
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
    $ADCSession = [PSObject]@{
        ManagementURL = $ManagementURL;
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
        Username      = $Credential.UserName;
        Version       = "UNKNOWN";
    }
    
    try {
        Write-Verbose -Message "Trying to retrieve the ADC version"
        $params = @{
            Uri           = "$($ManagementURL.AbsoluteUri)nitro/v1/config/nsversion"
            Method        = 'GET'
            WebSession    = $ADCSession.WebSession
            ContentType   = 'application/json'
            ErrorVariable = 'restError'
            Verbose       = $false
        }
        $response = Invoke-RestMethod @params
        Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
        $ADCSession.version = ($response.nsversion.version.Split(","))[0]
    } catch {
        Write-Verbose -Message "Error. See response: `n$($response | Format-List -Property * | Out-String)"
    }
    $Script:ADCSession = $ADCSession
        
    if ($PassThru) {
        return $ADCSession
    }
}

function Invoke-ADCRestApi {
    <#
        .SYNOPSIS
            Invoke ADC NITRO REST API
        .DESCRIPTION
            Invoke ADC NITRO REST API
        .PARAMETER ADCSession
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
        [alias("Session")]
        [Parameter(Mandatory = $true)]
        [PSObject]$ADCSession,
    
        [Parameter(Mandatory = $true)]
        [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
        [string]$Method,
    
        [Parameter(Mandatory = $true)]
        [string]$Type,
    
        [string]$Resource,
    
        [string]$Action,
    
        [hashtable]$Arguments = @{ },
            
        [ValidateCount(0, 1)]
        [hashtable]$Query = @{ },
    
        [switch]$Stat = $false,
    
        [ValidateScript( { $Method -eq 'GET' })]
        [hashtable]$Filters = @{ },
    
        [ValidateScript( { $Method -ne 'GET' })]
        [hashtable]$Payload = @{ },
    
        [switch]$GetWarning = $false,
    
        [ValidateScript( { $Method -eq 'GET' })]
        [switch]$Summary = $false,
    
        [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
        [string]$OnErrorAction = 'EXIT',
            
        [Switch]$Clean
    )
    # https://github.com/devblackops/NetScaler
    if ([string]::IsNullOrEmpty($($ADCSession.ManagementURL.AbsoluteUri))) {
        throw "ERROR. Probably not logged into the ADC"
    }
    if ($Stat) {
        $uri = "$($ADCSession.ManagementURL.AbsoluteUri)nitro/v1/stat/$Type"
    } else {
        $uri = "$($ADCSession.ManagementURL.AbsoluteUri)nitro/v1/config/$Type"
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
            $uri += $Query.GetEnumerator() | ForEach-Object { "?$($_.Name)=$([System.Uri]::EscapeDataString($_.Value))" }
        }
        if ($Summary) {
            $uri += "?view=$([System.Uri]::EscapeDataString("summary"))"
        }
    }
    Write-Verbose -Message "URI: $uri"
    $jsonPayload = $null
    if ($Method -ne 'GET') {
        $warning = if ($GetWarning) { 'YES' } else { 'NO' }
        $hashtablePayload = @{ }
        $hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#> }
        $hashtablePayload.$Type = $Payload
        $jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100
        Write-Verbose -Message "Method: $Method | Payload:`n$jsonPayload"
    }
        
    $response = $null
    $restError = $null
    try {
        $restError = @()
        $restParams = @{
            Uri           = $uri
            ContentType   = 'application/json'
            Method        = $Method
            WebSession    = $ADCSession.WebSession
            ErrorVariable = 'restError'
            Verbose       = $false
        }
        if ($Method -ne 'GET') {
            $restParams.Add('Body', $jsonPayload)
        }
        $response = Invoke-RestMethod @restParams
			
    } catch [Exception] {
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            Write-Warning -Message 'Connection closed due to reboot'
        } else {
            try {
                $response = $restError.Message | ConvertFrom-Json
            } catch {
                throw $_
            }
        }
    }
    if ($response -and $type) {
        $response | Add-Member -Membertype NoteProperty -Name type -value $Type
    }
    if ($response.severity -eq 'ERROR') {
        throw "Error. See response: `n$($response | Format-List -Property * | Out-String)"
    } 
    if (-Not [String]::IsNullOrEmpty($response)) {
        return $response
    }
}

function ConvertFrom-ADCVersion {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $Session
    )
    Process {
        try {
            if (-Not ($Session.Version -is [Version])) {
                $RawVersion = Select-String -InputObject $Session.Version -Pattern '[0-9]+\.[0-9]+' -AllMatches
                return [Version]"$($RawVersion.Matches[0].Value).$($RawVersion.Matches[1].Value)"
            } else {
                return $Session.Version
            }
        } catch {
            return [Version]"0.0"
        }
    }
}

function Expand-ADCResult {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $Result
    )
    
     
    Process {
        try {
            $Result | Select-Object -ExpandProperty $($Result.type) -ErrorAction Stop
        } catch {
            Write-Verbose "ERROR: $_.Exception.Message"
            $Result
        }
    }
     
    
     
}
    
function Write-ADCText {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $Result,
            
        [Switch]$PassThru
    )
        
         
    process {
        switch ($Result.severity) {
            "ERROR" { Write-Host -ForeGroundColor Red "ERROR [$($Result.errorcode)] $($Result.message)"; break }
            "NONE" { Write-Host -ForeGroundColor Green "Done"; break }
            "WARNING" { Write-Host -ForeGroundColor Yellow "WARNING $($Result.message)"; break }
            $null { Write-Host -ForeGroundColor Yellow "N/A"; break }
            default { "Something else happened |$($Result.severity)|"; break }
        }
    }
        
    end {
        if ($PassThru) { $Result }
    }
     
}
    
function Invoke-CheckADCSession {
    <#
        .SYNOPSIS
            Verify and retrieve an active sessionvariable
        .DESCRIPTION
            Verify and retrieve an active sessionvariable
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .NOTES
            File Name : Invoke-CheckADCSession
            Version   : v0.1
            Author    : John Billekens
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [cmdletbinding()]
    param(
        $ADCSession = $Script:ADCSession
    )
    if ([String]::IsNullOrEmpty($ADCSession)) {
        throw "Connect to the Citrix ADC Applicance first!"
    } else {
        return $ADCSession
    }
}
    
function Invoke-GetADCHANode {
    <#
        .SYNOPSIS
            Get HA Node Info
        .DESCRIPTION
            Get HA Node Info
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Filter
            Specify a filter
            -Filter @{"Ipaddress"="10.254.0.11";"State"="Primary"}
        .PARAMETER Summary
            If specified a subset of info will be returned
        .EXAMPLE
            Invoke-GetADCHANode -Summary
        .NOTES
            File Name : Invoke-GetADCHANode
            Version   : v0.1
            Author    : John Billekens
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [cmdletbinding()]
    param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        #
        [Parameter(ParameterSetName = 'Filter')]
        [hashtable]$Filter = @{ },
    
        [Switch]$Summary
    )
    try {
        Write-Verbose "$($ADCSession | convertto-json -compress)"
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type hanode -Filter $Filter -Summary:$Summary
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}
    
function Invoke-GetADCNSIP {
    <#
        .SYNOPSIS
            Get NSIP Info
        .DESCRIPTION
            Get NSIP Info
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Filter
            Specify a filter
            -Filter @{"type"="NSIP"}
        .PARAMETER Summary
            If specified a subset of info will be returned
        .EXAMPLE
            Invoke-GetADCHANode -Summary
        .NOTES
            File Name : Invoke-GetADCHANode
            Version   : v0.1
            Author    : John Billekens
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [cmdletbinding()]
    param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        #
        [hashtable]$Filter = @{ },
    
        [Switch]$Summary = $false
    )
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type nsip -Filter $Filter -Summary:$Summary -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}
    
function Invoke-GetADCNSConfig {
    <#
        .SYNOPSIS
            Get NSIP Info
        .DESCRIPTION
            Get NSIP Info
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Filter
            Specify a filter
            -Filter @{"type"="NSIP"}
        .EXAMPLE
            Invoke-GetADCNSConfig
        .NOTES
            File Name : Invoke-GetADCNSConfig
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ns/nsconfig/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [cmdletbinding()]
    param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        [hashtable]$Filter = @{ }
    )
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type nsconfig -Filter $Filter -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-GetADCSSLCertKey {
    <#
        .SYNOPSIS
            Get SSL Certificate names (CertKey)
        .DESCRIPTION
            Get SSL Certificate names (CertKey)
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Filter
            Specify a filter
            -Filter @{"certkey"="star_domain.com"}
			or -Filter ${"status"="Expired"}
        .PARAMETER Summary
            If specified a subset of info will be returned
        .EXAMPLE
            Invoke-GetADCSSLCertKey
        .NOTES
            File Name : Invoke-GetADCSSLCertKey
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ssl/sslcertkey/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [cmdletbinding()]
    param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        [hashtable]$Filter = @{ },
    
        [Switch]$Summary = $false
    )
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filter $Filter -Summary:$Summary -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-GetADCSystemFile {
    <#
        .SYNOPSIS
            Get SystemFile information
        .DESCRIPTION
            Get SystemFile information
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER FileLocation
            Specify a path, e.g. "/nsconfig/ssl/"
        .PARAMETER FileName
            Specify a filename
        .EXAMPLE
            Invoke-GetADCSystemFile -FileLocation "/nsconfig/ssl/"
        .EXAMPLE
            Invoke-GetADCSystemFile -FileLocation "/nsconfig" -FileName "ns.conf"
        .NOTES
            File Name : Invoke-GetADCSystemFile
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/system/systemfile/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [cmdletbinding()]
    param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        [Parameter(Mandatory = $true)]
        [alias("FilePath")]
        [String]$FileLocation,
			
        [hashtable]$Filter = @{ },
    
        [String]$FileName
    )
    $Arguments = @{ "filelocation" = $($FileLocation.Replace('\', '/').TrimEnd('/')) }
		
    if ($PSBoundParameters.ContainsKey('FileName')) {
        $Arguments += @{ "filename" = $FileName }
    }
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Filter $Filter -Arguments $Arguments -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-GetADCSystemFileDirectories {
    [cmdletbinding()]
    param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        [Parameter(Mandatory = $true)]
        [alias("FilePath")]
        [String]$FileLocation
    )
    $Output = @()
    $Output += "$FileLocation"
    try {
        $dirs = Invoke-GetADCSystemFile -FileLocation $FileLocation -ADCSession $Session | Expand-ADCResult | Where-Object { $_.filemode -eq "DIRECTORY" } | Foreach-Object { "$($_.filelocation)/$($_.filename)" }
    } catch {
        
    }
    if ($dirs.count -gt 0) {
        $Output += $dirs | ForEach-Object { Invoke-GetADCSystemFileDirectories -FileLocation $_ -ADCSession $Session }
    }
    return $Output
}

function Invoke-GetADCSSLCertKeyBinding {
    <#
        .SYNOPSIS
            Get Binding information for CertKeys (TLS Certificates)
        .DESCRIPTION
            Get Binding information for CertKeys (TLS Certificates)
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER CertKey
            Specify a CertKey name
        .EXAMPLE
            Invoke-GetADCSSLCertKeyBinding
        .EXAMPLE
            Invoke-GetADCSSLCertKeyBinding -CertKey "domain.com"
        .NOTES
            File Name : Invoke-GetADCSSLCertKeyBinding
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ssl/sslcertkey_binding/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [CmdletBinding(DefaultParameterSetName = "GetAll")]  
    Param(
        
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
			
        [Parameter(ParameterSetName = "GetResource", Mandatory = $true)]
        [String]$CertKey
    )

    try {
        if ($PSBoundParameters.ContainsKey('CertKey')) {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type sslcertkey_binding -Resource $CertKey -GetWarning
        } else {
            $Query = @{"bulkbindings" = "yes"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type sslcertkey_binding -Query $Query -GetWarning
        }
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-GetADCCSvServer {
    <#
        .SYNOPSIS
            Get Content Switch Virtual Server details
        .DESCRIPTION
            Get Content Switch Virtual Server details
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Name
            Specify a Content Switch Virtual Server Name
        .PARAMETER Count
            If specified, the number of Content Switch Virtual Servers will be returned
        .PARAMETER Filter
            Specify a filter
            -Filter @{"curstate"="UP"}
        .PARAMETER Summary
            When specified, only a subset of information is returned
        .EXAMPLE
            Invoke-GetADCCSvServer
        .EXAMPLE
            Invoke-GetADCCSvServer -Name "cs_domain.com_https"
        .NOTES
            File Name : Invoke-GetADCSSLCertKeyBinding
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/cs/csvserver/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [CmdletBinding(DefaultParameterSetName = "GetAll")]  
    Param(
        
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
			
        [Parameter(ParameterSetName = "GetResource", Mandatory = $true)]
        [String]$Name,
            
        [Parameter(ParameterSetName = "GetAll")]
        [Switch]$Count = $false,
			
        [hashtable]$Filter = @{ },
    
        [Switch]$Summary = $false
    )
    $Query = @{ }
    try {
        if ($PSBoundParameters.ContainsKey('Count')) {
            $Query = @{ "count" = "yes" }
        }			
        if ($PSBoundParameters.ContainsKey('Name')) {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type csvserver -Resource $Name -Summary:$Summary -Filter $Filter -GetWarning
        } else {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type csvserver -Summary:$Summary -Filter $Filter -Query $Query -GetWarning
        }
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-EnableADCNSFeature {
    <#
        .SYNOPSIS
            Enable one or multiple ADC features
        .DESCRIPTION
            Enable one or multiple ADC features
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Feature
            Enter one or more Features that need to be enabled
        .EXAMPLE
            Invoke-EnableADCNSFeature -Feature LB
        .EXAMPLE
            Invoke-EnableADCNSFeature -Feature lb, cs, rewrite, responder
        .NOTES
            File Name : Invoke-EnableADCNSFeature
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ns/nsfeature/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [CmdletBinding()]  
    Param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),

        [ValidateSet('wl', 'sp', 'lb', 'cs', 'cr', 'sc', 'cmp', 'pq', 'ssl', 'gslb', 'hdosp', 'routing', 'cf', 'ic', 'sslvpn', `
                'aaa', 'ospf', 'rip', 'bgp', 'rewrite', 'ipv6pt', 'appfw', 'responder', 'htmlinjection', 'push', 'appflow', `
                'cloudbridge', 'isis', 'ch', 'appqoe', 'contentaccelerator', 'rise', 'feo', 'lsn', 'rdpproxy', 'rep', `
                'urlfiltering', 'videooptimization', 'forwardproxy', 'sslinterception', 'adaptivetcp', 'cqa', 'ci', 'bot')]
        [String[]]$Feature = @()
    )
    try {
        $Payload = @{"feature" = $Feature }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsfeature -Payload $payload -Action enable -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-DisableADCNSFeature {
    <#
        .SYNOPSIS
            Disable one or multiple ADC features
        .DESCRIPTION
            Disable one or multiple ADC features
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Feature
            Enter one or more Features that need to be disabled
        .EXAMPLE
            Invoke-DisableADCNSFeature -Feature LB
        .EXAMPLE
            Invoke-DisableADCNSFeature -Feature lb, cs, rewrite, responder
        .NOTES
            File Name : Invoke-DisableADCNSFeature
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ns/nsfeature/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [CmdletBinding()]  
    Param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),

        [ValidateSet('wl', 'sp', 'lb', 'cs', 'cr', 'sc', 'cmp', 'pq', 'ssl', 'gslb', 'hdosp', 'routing', 'cf', 'ic', 'sslvpn', `
                'aaa', 'ospf', 'rip', 'bgp', 'rewrite', 'ipv6pt', 'appfw', 'responder', 'htmlinjection', 'push', 'appflow', `
                'cloudbridge', 'isis', 'ch', 'appqoe', 'contentaccelerator', 'rise', 'feo', 'lsn', 'rdpproxy', 'rep', `
                'urlfiltering', 'videooptimization', 'forwardproxy', 'sslinterception', 'adaptivetcp', 'cqa', 'ci', 'bot')]
        [String[]]$Feature = @()
    )
    try {
        $Payload = @{"feature" = $Feature }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsfeature -Payload $payload -Action disable -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-GetADCNSFeature {
    <#
        .SYNOPSIS
            Get feature state
        .DESCRIPTION
            Get feature state
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .EXAMPLE
            Invoke-GetADCNSFeature
        .NOTES
            File Name : Invoke-GetADCNSFeature
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ns/nsfeature/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [CmdletBinding()]  
    Param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession)
    )
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type nsfeature
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-GetADCSSLCertLink {
    <#
        .SYNOPSIS
            Get TLS Certificate links
        .DESCRIPTION
            Get TLS Certificate links
        .PARAMETER ADCSession
            Specify an active session (Output from Connect-ADC)
        .PARAMETER Filter
            Specify a filter
            -Filter @{certkeyname="domain.com"}
			or -Filter ${"linkcertkeyname"="Lets Encrypt Authority X3"}
        .PARAMETER Summary
            If specified a subset of info will be returned
        .EXAMPLE
            Invoke-GetADCSSLCertLink
        .EXAMPLE
            Invoke-GetADCSSLCertLink -Filter @{certkeyname="domain.com"}
        .NOTES
            File Name : Invoke-GetADCSSLCertLink
            Version   : v0.1
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ssl/sslcertlink/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
        #>
    [CmdletBinding()]  
    Param(
        [hashtable]$ADCSession = (Invoke-CheckADCSession),
            
        [hashtable]$Filter = @{ },
    
        [Switch]$Summary = $false
    )
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertlink -Filter $Filter -Summary:$Summary -GetWarning
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        $response = $null
    }
    return $response
}

function Invoke-DeleteADCCertKey {
    [cmdletbinding()]
    param(
        [hashtable]$Session = (Invoke-CheckADCSession),
            
        [String]$CertKey,
            
        [Switch]$Text
    )
    try {
        $response = Invoke-ADCRestApi -Session $Session -Method DELETE -Type sslcertkey -Resource $CertKey
    } catch {
        $response = $null
    }
    return $response
}
    
function Invoke-DeleteADCSystemFile {
    [cmdletbinding()]
    param(
        [hashtable]$Session = (Invoke-CheckADCSession),
            
        [String]$FileName,
            
        [String]$FileLocation
    )
    try {
        $Arguments = @{"filelocation" = "$FileLocation"; }
        $response = Invoke-ADCRestApi -Session $Session -Method DELETE -Type systemfile -Resource $FileName -Arguments $Arguments
    } catch {
        $response = $null
    }
    return $response
}
    
function Invoke-SaveADCConfig {
    [cmdletbinding()]
    param(
        [hashtable]$Session = (Invoke-CheckADCSession)
    )
    try {
        $response = Invoke-ADCRestApi -Session $Session -Method POST -Type nsconfig -Action save
    } catch {
        $response = $null
    }
    return $response
}
    
function Invoke-BackupADCConfig {
    [cmdletbinding()]
    param(
        [hashtable]$Session = (Invoke-CheckADCSession),
            
        [String]$Name = "ADCBackup_$((Get-Date).ToString("yyyyMMdd_HHmm"))",
    
        [String]$Comment = "Backup created by PoSH function Invoke-BackupADCConfig",
            
        [ValidateSet("full", "basic")]
        [String]$Level = "full",
            
        [alias("SaveConfig")]
        [Switch]$SaveConfigFirst
    )
    if ($SaveConfigFirst) {
        Write-Verbose "SaveConfig parameter specified, saving config"
        Invoke-SaveADCConfig -Session $Session | Out-Null
    }
    try {
        $payload = @{"filename" = "$Name"; "level" = "$($Level.ToLower())"; "comment" = "$Comment" }
        $response = Invoke-ADCRestApi -Session $Session -Method POST -Type systembackup -Payload $payload -Action create -GetWarning
    } catch {
        $response = $null
    }
    return $response
}
