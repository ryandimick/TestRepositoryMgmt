function Ignore-SelfSignedCerts {
    add-type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Invoke-OpConRestMethod {
    param(
        [ValidateNotNullorEmpty()]
        [String]$Uri,
        [ValidateNotNullorEmpty()]
        [String]$Method,
        [object]$Body = $null
    )

    if (!$Global:OpconRESTApiUrl -or !$Global:OpconRESTApiAuthHeader)
    {
        Write-Warning "No values for Opcon REST Api.  Please use Logon-OpConApi before using cmdlet."
        throw [System.Exception] "Invalid OpCon REST API Values"
    }

    $uri = $Global:OpconRESTApiUrl + $Uri
    
    Write-Verbose("Sending Web Request...")
    try
    {
        if ($Body -eq $null)
        {
            $response = Invoke-RestMethod -Method $Method -Uri $uri -Headers $Global:OpconRESTApiAuthHeader -ErrorVariable $RestException
        }
        else
        {
            $Body = ConvertTo-Json $Body
            Write-Verbose $Body
            $response = Invoke-RestMethod -Method $Method -Uri $uri -Headers $Global:OpconRESTApiAuthHeader -Body $Body -ContentType "application/json" -ErrorVariable $RestException
        }
        Write-Verbose ("`n")
        Write-Verbose("RESPONSE:")
        Write-Verbose(ConvertTo-Json $response)
        return $response
    }
    catch
    {
        Write-Warning ("Error")
        Write-Warning ("StatusCode: " + $_.Exception.Response.StatusCode.value__)
	    Write-Warning ("StatusDescription: " + $_.Exception.Response.StatusDescription)
        $opconApiError = ConvertFrom-Json $_.ErrorDetails.Message
        Write-Warning ("ErrorCode: " + $opconApiError.code)
        Write-Warning ("ErrorMessage: " + $opconApiError.message)
        throw
	    ##exit $_.Exception.Response.StatusCode.value__
    }
}

function Get-OpConApiToken {
[cmdletbinding()]
param(
    [string] $Url,
    [string] $User,
    [string] $Password
    )
$tokensUri = -join($Url, "/api/tokens")
Write-Host ("Retrieving authorization token...")
Write-Host ("Uri: " + $tokensUri)
Write-Host ("User: " + $User)
$tokenObject = @{
    user = @{
        loginName = $User
        password = $Password
    }
    tokenType = @{
        type = "User"
    }
}
try
{
    Ignore-SelfSignedCerts
    $token = Invoke-RestMethod -Method Post -Uri $tokensUri -Body (ConvertTo-Json $tokenObject) -ContentType "application/json" -ErrorVariable $RestException
}
catch
{
    $error = ConvertFrom-Json $_.ErrorDetails.Message
    Write-Host ("Unable to fetch token for user '" + $user + "'")
    Write-Host ("Error Code: " + $error.code)
    Write-Host ("Message: " + $error.message)
    ##Write-Host ("StatusCode: " + $_.Exception.Response.StatusCode.value__)
    ##Write-Host ("StatusDescription: " + $_.Exception.Response.StatusDescription)
    ##Write-Host ("Message: " + $_[0].message)
    ##$Global:OpConRESTAPIException = $_
    throw
    ##exit $_.Exception.Response.StatusCode.value__
}
Write-Host ("Token retrieved successfully, Id: " + $token.id + ", Valid Until: " + $token.validUntil)
return $token
}

function Get-OpConApiAuthHeader {
param(
    [string] $Token
    )
    $authHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $authHeader.Add("Authorization", ("Token " + $Token))
    return $authHeader
}


function Login-RestApi {
[cmdletbinding()]
param(
    [string] $ApiUrl,
    [string] $OpConUser,
    [string] $OpConPassword
    )

    Write-Verbose ("Parameters =")
    Write-Verbose ("ApiUrl: " + $ApiUrl)
    Write-Verbose ("OpConUser: " + $OpConUser)
    Write-Verbose ("OpConPassword: (hidden)")

    $ApiUrl = $ApiUrl.ToLower().TrimEnd("/").TrimEnd("/api")

    Write-Host ("Logging in to OpCon REST API: " + $ApiUrl)

    $Global:OpconRESTApiUrl = $ApiUrl
    $Global:OpconRESTApiUser = $OpConUser
    $Global:OpConRESTApiPassword = $OpConPassword
    $token = Get-OpConApiToken -Url $ApiUrl -User $OpConUser -Password $OpConPassword
    $Global:OpconRESTApiToken = $token.id

    $Global:OpconRESTApiAuthHeader = Get-OpConApiAuthHeader -Token $token.id
    Write-Host ('Token successfully stored for future calls in session.')
}

function Get-DailySchedule{
[cmdletbinding()]
param(
    [int] $ScheduleDate,
    [string] $ScheduleName,
    [string] $Categories = $null
)
    Write-Host ("Retrieving schedule: " + $ScheduleName + " for date: " + $ScheduleDate)
    $uri = "/api/dailySchedules?date=" + $ScheduleDate.ToString() + "&name=" + $ScheduleName
    $response = Invoke-OpConRestMethod -Uri $uri -Method GET

    if ($response -ne $null)
    {
        $dailySchedules = $response | ForEach-Object -Process { New-DailySchedule -Id $_.id -Name $_.name -Status (New-ScheduleStatus -Id $_.status.id -Description $_.status.description -Category $_.status.category -ContainsFailedJobs $_.status.containsFailedJobs) -Instance $_.instance -Date $_.date -Path $_.path -EndTime $_.endTime -DefinedStartTime $_.definedStartTime -MasterId $_.masterId -Duration $_.duration -ComputedStartTime (New-ComputedStartTime -Time $_.computedStartTime.time -IsEstimated $_.computedStartTime.isEstimated) }
        Write-Host ($dailySchedules.Count.ToString() + " daily schedules found.")
        if ($dailySchedules.Count -eq 0)
        {
            return $null;
        }
        Write-Host ($dailySchedules | Format-Table | Out-String)
        return $dailySchedules[0]
    }           
    else
    {
        Write-Host ("No daily schedules found")
        return $null
    }
}

function New-DailySchedule{
    param(
        [string] $Id = $null,
        [string] $Name,
        [ScheduleStatus] $Status = $null,
        [int] $Instance,
        [string] $Date,
        [string] $Path,
        [string] $EndTime,
        [string] $DefinedStartTime,
        [int] $MasterId,
        [double] $Duration,
        [ComputedStartTime] $ComputedStartTime = $null
    )

    $dailySchedule = [DailySchedule]@{
        Id = $Id
        Name = $Name
        Status = $Status
        Instance = $Instance
        Date = $Date
        Path = $Path
        EndTime = $EndTime
        DefinedStartTime = $DefinedStartTime
        MasterId = $MasterId
        Duration = $Duration
        ComputedStartTime = $ComputedStartTime
    }

    return $dailySchedule
}

function New-ScheduleStatus{
    param(
        [ValidateNotNullorEmpty()]
        [int] $Id,
        [ValidateNotNullorEmpty()]
        [string] $Description,
        [ValidateNotNullorEmpty()]
        [string] $Category,
        [ValidateNotNullorEmpty()]
        [boolean] $ContainsFailedJobs
    )

    $scheduleStatus = [ScheduleStatus]@{
        Id = $Id
        Description = $Description
        Category = $Category
        ContainsFailedJobs = $ContainsFailedJobs
    }

    return $scheduleStatus
}

function New-ComputedStartTime{
    param(
        [ValidateNotNullorEmpty()]
        [string] $Time,
        [ValidateNotNullorEmpty()]
        [boolean] $IsEstimated
    )

    $computedStartTime = [ComputedStartTime]@{
        Time = $Time
        IsEstimated = $IsEstimated
    }

    return $computedStartTime
}

class ScheduleStatus
{
    [ValidateNotNullorEmpty()] [int] $Id
    [ValidateNotNullorEmpty()] [string] $Description
    [ValidateNotNullorEmpty()] [string] $Category
    [ValidateNotNullorEmpty()] [boolean] $ContainsFailedJobs
}

class ComputedStartTime
{
    [ValidateNotNullorEmpty()] [string] $Time
    [ValidateNotNullorEmpty()] [boolean] $IsEstimated
}

class DailySchedule
{
    [string] $Id = $null
    [string] $Name
    [ScheduleStatus] $Status = $null
    [int] $Instance
    [string] $Date
    [string] $Path
    [string] $EndTime
    [string] $DefinedStartTime
    [int] $MasterId
    [double] $Duration
    [ComputedStartTime] $ComputedStartTime = $null
}


Export-ModuleMember -Function Login-RestApi
Export-ModuleMember -Function Get-DailySchedule