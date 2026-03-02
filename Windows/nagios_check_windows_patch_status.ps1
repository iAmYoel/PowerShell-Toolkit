<#
    .SYNOPSIS
        Check the status of the latest Windows cumulative update on a local server.
    .DESCRIPTION
        This script uses the Microsoft.Update.Session COM object (Windows Update API, a.k.a WUA) to query the Windows Update history for installed cumulative updates (non-preview) on Windows Server 2016 or newer. It also tries to corroborate this information against Microsoft Online web site.
        It checks DISM packages as a fallback method if the WUA is not available or fails and tries to corroborate it against Microsoft online web site. Install date of the patch is used as fallback if the corroboration againts Microsoft Online fails.
        It compares the latest installed update against the current Patch Tuesday cycle per default to determine if the system is up-to-date. If custom thresholds are provided, the subsequent month's Patch Tuesday from the installed patch is used instead.
        The logic is that when patch tuesday is released, previous months patch is considered up-to-date until next patch tuesday is released, after that a Warning status is triggered when you are more than one month old. If another month or more passes by, a Critical status is triggered.
        This logic can be overridden by providing custom thresholds as parameters where these are used instead and compared against the subsequent month's Patch Tuesday from the patch that is installed.
        The script returns a Nagios-compatible status code and message based on this evaluation.
    .PARAMETER WarningDaysAfterPatchTuesday
        The number of days after the second Tuesday of the month (Patch Tuesday) to wait before returning a Warning status if the subsequent cumulative update from the installed update is not installed.
        Must be a positive integer. Optional to use but if CriticalDaysAfterPatchTuesday is specified, this parameter becomes mandatory.
    .PARAMETER CriticalDaysAfterPatchTuesday
        The number of days after the second Tuesday of the month (Patch Tuesday) to wait before returning a Critical status if the subsequent cumulative update from the installed update is not installed.
        Must be a positive integer and greater than WarningDaysAfterPatchTuesday. Optional to use but if WarningDaysAfterPatchTuesday is specified, this parameter becomes mandatory.
    .NOTES
        Requires local execution with administrative privileges to query Windows Update.
        Tested on Windows Server 2016, 2019, 2022 and 2025.
        All exit-codes for status UNKNWON are temporarily assigned the exit-code 0 to avoid false alarms in monitoring systems during a trial phase.
    .EXAMPLE
        PS> .\adv_check_windows_patch_status.ps1
        OK - Cumulative Update October-2023 patch (KB5029244) - InstallDate: 2023-10-12 14:23 (via WUA-Title)
    .EXITCODES
        0 = OK       (Latest cumulative update is installed and up-to-date)
        1 = WARNING  (Cumulative update installed but more than one month old)
        2 = CRITICAL (Cumulative update is two or more month old or missing)
        3 = UNKNOWN  (Update status could not be determined through either WUA or DISM)
    .REQUIREMENTS
        Windows Server 2016 or later.
        Windows Update service (wuauserv) must be enabled and DataStore.edb needs to exist for the WUA check to work. DISM needs to be functional for the fallback check to work.
        Internet access is required for online patch information lookup to corroborate WUA patch title and also corroborate DISM results, or else WUA title or DISM install date is used as fallback, in that order.
        PowerShell and .NET Framework needs to be available.
    .AUTHOR
        Yoel Abraham (Yoel.Abraham@advania.se)
#>
[CmdletBinding(DefaultParameterSetName='MonthBased')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='DayBased')]
    [int]$WarningDaysAfterPatchTuesday,

    [Parameter(Mandatory=$true, ParameterSetName='DayBased')]
    [ValidateScript({
        if ($_ -le $WarningDaysAfterPatchTuesday) {
            throw "CriticalDaysAfterPatchTuesday ($_) must be greater than WarningDaysAfterPatchTuesday ($WarningDaysAfterPatchTuesday)."
        }
        $true
    })]
    [int]$CriticalDaysAfterPatchTuesday
)

# Flag to indicate if custom thresholds are being used
$useCustomThresholds = ($PSCmdlet.ParameterSetName -eq 'DayBased')

# --- Functions ---

function Test-WuaPrerequisites {
    <#
    .SYNOPSIS
        Tests if the prerequisites for using the Windows Update Agent (WUA) COM object are met.
    .DESCRIPTION
        This function checks three conditions:
        1. The 'wuauserv' (Windows Update) service exists.
        2. The 'wuauserv' service is not disabled.
        3. The Windows Update database file ('DataStore.edb') exists.
        It returns an object detailing whether WUA can be used and the reasons if not.
    .OUTPUTS
        [pscustomobject] An object with the following properties:
            - CanUseWuaCom [bool]: $true if prerequisites are met, otherwise $false.
            - Reasons [array]: A list of reasons why WUA cannot be used.
            - WuaService [pscustomobject]: Information about the 'wuauserv' service.
    #>
    [CmdletBinding()]
    param()

    # Initialize a result object to store prerequisite check outcomes.
    $results = @{
        CanUseWuaCom = $true
        Reasons      = @()
        WuaService   = $null
        Dependencies = @()
    }

    try {
        # 1) Attempt to get the 'wuauserv' service object.
        $wuaService = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
        if (-not $wuaService) {
            $results.CanUseWuaCom = $false
            $results.Reasons += "Service 'wuauserv' not found."
            return [pscustomobject]$results
        }

        # Store basic service information.
        $results.WuaService = [pscustomobject]@{
            Name      = 'wuauserv'
            StartType = $wuaService.StartType.ToString()
            Status    = $wuaService.Status.ToString()
        }

        # 2) If the service is disabled, the COM API cannot be used.
        if ($results.WuaService.StartType -eq 'Disabled') {
            $results.CanUseWuaCom = $false
            $results.Reasons += "Windows Update service 'wuauserv' has StartType 'Disabled'. COM usage not possible."
            return [pscustomobject]$results
        }

        # 3) Check for the presence of the local Windows Update database file.
        $wuDbPath = "$env:WINDIR\SoftwareDistribution\DataStore\DataStore.edb"
        if (-not (Test-Path -LiteralPath $wuDbPath)) {
            $results.CanUseWuaCom = $false
            $results.Reasons += "Windows Update database file missing: $wuDbPath"
            return [pscustomobject]$results
        }

        # If all checks pass, clear any informational reasons and return success.
        if ($results.CanUseWuaCom) { $results.Reasons = @() }
        return [pscustomobject]$results

    } catch {
        # Catch any unexpected errors during the check.
        $results.CanUseWuaCom = $false
        $results.Reasons += "Unexpected error during prerequisites check: $($_.Exception.Message)"
        return [pscustomobject]$results
    }
}

function Get-KBsFromTitle {
    <#
    .SYNOPSIS
        Extracts all KB numbers (e.g., "KB1234567") from a given string.
    .PARAMETER Title
        The string to search for KB numbers.
    .OUTPUTS
        [array] An array of strings, where each string is a found KB number.
    #>
    param([string]$title)
    if (-not $title) { return @() }
    # Use regex to find all occurrences of "KB" followed by digits.
    return ([regex]::Matches($title, 'KB\d+')) | ForEach-Object { $_.Value }
}

function Get-PatchYearMonthFromTitle {
    <#
    .SYNOPSIS
        Extracts the patch year and month (YYYY-MM) from an update title string.
    .DESCRIPTION
        This function is designed to parse update titles that start with a date format
        like "2025-10 Cumulative Update...".
    .PARAMETER Title
        The string to parse.
    .OUTPUTS
        [string] The formatted "YYYY-MM" string if found; otherwise, $null.
    #>
    param([string]$title)
    if (-not $title) { return $null }
    # Match a pattern like "YYYY-MM" at the beginning of the string.
    $match = [regex]::Match($title, '^(?<ym>\d{4}-\d{2})')
    if ($match.Success) { return $match.Groups['ym'].Value }
    return $null
}

function Get-SecondTuesday {
    <#
    .SYNOPSIS
        Calculates the date of the second Tuesday for a given month.
    .DESCRIPTION
        Microsoft releases its main security patches on the second Tuesday of each month,
        known as "Patch Tuesday." This function determines that specific date.
    .PARAMETER Date
        A datetime object representing any day within the desired month.
    .OUTPUTS
        [DateTime] The date of the second Tuesday of that month.
    #>
    param([datetime]$Date)
    # Start from the first day of the given month.
    $firstDay = Get-Date $Date -Day 1
    # Calculate days needed to get from the first day's weekday to the first Tuesday.
    $daysToTuesday = (2 - $firstDay.DayOfWeek.value__) % 7
    # The second Tuesday is 7 days after the first Tuesday.
    $secondTuesday = $firstDay.AddDays($daysToTuesday + 7)
    return [DateTime]$secondTuesday
}

function Get-MsftPatchInfo {
    <#
    .SYNOPSIS
        Scrapes Microsoft's support pages to find details about a specific patch.
    .DESCRIPTION
        This function can find patch information (KB number, OS build, release date)
        by either a KB number or an OS build number. It first tries the direct KB
        article page and falls back to searching the Windows Update History pages.
        This is used when local information is incomplete.
    .PARAMETER KBNumber
        The KB number to look up (e.g., "KB5005565").
    .PARAMETER BuildNumber
        The OS build number to look up (e.g., "19044.1237").
    .PARAMETER TimeoutSeconds
        The timeout for web requests.
    .OUTPUTS
        [pscustomobject] An object containing the found patch details.
    #>
    [CmdletBinding(DefaultParameterSetName='ByBuild')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='ByKB')]
        [ValidatePattern('^KB\d+$')]
        [string]$KBNumber,

        [Parameter(Mandatory=$true, ParameterSetName='ByBuild')]
        [ValidatePattern('^\d{5,}(\.\d+){1,3}$')]
        [string]$BuildNumber,

        [int]$TimeoutSeconds = 30
    )

    # --- Helpers & mappings ---
    # Maps major OS build numbers to Windows Server versions.
    # When new Windows Server versions are released, this map should be updated.
    $osMap = @{
        '14393' = '2016-1607'
        '17763' = '2019-1809'
        '18362' = '2019-1903'
        '18363' = '2019-1909'
        '19043' = '2019-2004'
        '20348' = '2022'
        '25389' = '2022-23H2'
        '26100' = '2025'
    }

    # URLs for the official update history pages for each server version.
    # When new Windows Server versions are released, this map should be updated.
    $historyPages = @{
        "2016-1607" = "https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2016-update-history-4acfbc84-a290-1b54-536a-1c0430e9f3fd"
        "2019-1809" = "https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2019-update-history-725fc2e1-4443-6831-a5ca-51ff5cbcb059"
        "2019-1903" = "https://support.microsoft.com/en-us/topic/windows-10-update-history-e6058e7c-4116-38f1-b984-4fcacfba5e5d"
        "2019-1909" = "https://support.microsoft.com/en-us/topic/windows-10-update-history-53c270dc-954f-41f7-7ced-488578904dfe"
        "2019-2004" = "https://support.microsoft.com/en-us/topic/windows-10-update-history-24ea91f4-36e7-d8fd-0ddb-d79d9d0cdbda"
        "2019-20H2" = "https://support.microsoft.com/en-us/topic/windows-10-update-history-7dd3071a-3906-fa2c-c342-f7f86728a6e3"
        "2022"      = "https://support.microsoft.com/en-us/topic/windows-server-2022-update-history-e1caa597-00c5-4ab9-9f3e-8212fe80b2ee"
        "2022-23H2" = "https://support.microsoft.com/en-us/topic/windows-server-version-23h2-update-history-68c851ff-825a-4dbc-857b-51c5aa0ab248"
        "2025"      = "https://support.microsoft.com/en-us/topic/windows-server-2025-update-history-10f58da7-e57b-4a9d-9c16-9f1dcd72d7d7"
    }

    # Helper function to download web page content with a standard user agent.
    function Get-PageContent {
        param([string]$Url)
        try {
            $headers = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT; Win64; x64)' }
            $resp = Invoke-WebRequest -Uri $Url -Headers $headers -TimeoutSec $TimeoutSeconds -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop
            return $resp.Content
        } catch {
            return $null
        }
    }

    # Helper function for safe regex matching.
    function SafeMatch([string]$text, [string]$pattern) {
        if (-not $text) { return $null }
        $m = [regex]::Match($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($m.Success) { return $m } else { return $null }
    }

    # Helper to extract a value using multiple regex patterns and return it with context.
    function TryExtract ([string[]]$Patterns, [string]$Text, [int]$ContextChars = 80) {
        if (-not $Text) { return $null }
        foreach ($p in $Patterns) {
            $m = SafeMatch -text $Text -pattern $p
            if ($m) {
                # Get the matched value (from group 1 if it exists, otherwise the whole match).
                $val = if ($m.Groups.Count -gt 1) { $m.Groups[1].Value.Trim() } else { $m.Value.Trim() }
                # Create a snippet of text around the match for debugging/context.
                $idx = $m.Index
                $start = [Math]::Max(0, $idx - $ContextChars)
                $len = [Math]::Min($ContextChars*2 + $m.Length, $Text.Length - $start)
                $snippet = $Text.Substring($start, $len) -replace "[\r\n]+", " "
                return [PSCustomObject]@{ Value = $val; Pattern = $p; Snippet = $snippet }
            }
        }
        return $null
    }

    # Define regex patterns for extracting patch information from HTML.
    $datePatterns = @('([A-Z][a-z]+ \d{1,2},\s*\d{4})','(\d{4}-\d{2}-\d{2})')
    $kbPatterns   = @('\b(KB\d+)\b')
    $buildPatterns = @('OS\s*Build[:\s]*([\d]+(?:\.[\d]+)*)','\bBuild[:\s]*([\d]+(?:\.[\d]+){0,3})','([\d]{5,}\.[\d]+(?:\.[\d]+)*)')
    $oobPatterns = @('Out(?:[-\s]|<[^>]*>|&nbsp;)*of(?:[-\s]|<[^>]*>|&nbsp;)*Band')
    $pagePattern = '(?<PatchDate>\w+\s+\d{1,2},\s*\d{4}).*?(?<KB>KB\d+).*?OS Build\s+(?<BuildNumber>\d+(?:\.\d+)*).*?(?<OutOfBand>Out[-\s]?of[-\s]?Band)?'

    # Initialize a template for the result object.
    $result = [PSCustomObject]@{
        Found        = $false
        KBNumber     = $null
        OSBuild      = $null
        OutOfBand    = $null
        PatchDate    = $null
        ServerVersion= $null
        SourceUsed   = $null
        Reason       = $null
    }

    try {
        # --- LOGIC BRANCH: Search by KB Number ---
        if ($PSCmdlet.ParameterSetName -eq 'ByKB') {
            # ------------ Primary Method: Scrape the direct KB help page ------------
            $idOnly = $KBNumber -replace '^KB',''
            $kbUrl = "https://support.microsoft.com/help/$idOnly"
            $kbHtml = Get-PageContent -Url $kbUrl
            if ($kbHtml) {
                # Try to find the most relevant text block (title, H1) to parse.
                $candidate = $null
                $m = SafeMatch -text $kbHtml -pattern '<meta[^>]*(?:property|name)\s*=\s*["''](?:og:title|title)["''][^>]*content\s*=\s*["''](?<v>[^"'']+)["'']'
                if ($m) { $candidate = $m.Groups['v'].Value.Trim() }
                if (-not $candidate) {
                    $m = SafeMatch -text $kbHtml -pattern '<h1[^>]*>(?<v>.*?)</h1>'
                    if ($m) { $candidate = ($m.Groups['v'].Value -replace '<[^>]+>','').Trim() }
                }
                if (-not $candidate) {
                    $m = SafeMatch -text $kbHtml -pattern '<title[^>]*>(?<v>.*?)</title>'
                    if ($m) { $candidate = $m.Groups['v'].Value.Trim() }
                }
                # Fallback to searching the entire HTML body.
                if (-not $candidate) { $candidate = $kbHtml }

                # Attempt to extract KB, date, and build from the selected text.
                $kbFound    = TryExtract -Patterns $kbPatterns -Text $candidate
                $dateFound  = TryExtract -Patterns $datePatterns -Text $candidate
                $buildFound = TryExtract -Patterns $buildPatterns -Text $candidate
                $oobFound   = TryExtract -Patterns $oobPatterns -Text $candidate

                # Populate the result object with findings.
                $result.KBNumber  = if ($kbFound) { $kbFound.Value } else { $KBNumber }
                $result.PatchDate = if ($dateFound) { $dateFound.Value } else { $null }
                $result.OSBuild   = if ($buildFound) { $buildFound.Value } else { $null }
                $result.OutOfBand = if ($oobFound) { $true } else { $false }
                $result.SourceUsed= 'KBPage'

                # If we found the core info, we are done.
                if ($result.OSBuild -and $result.PatchDate) {
                    $result.Found = $true
                    return $result
                }
            } else {
                # If fetching the KB page failed, note it and prepare for fallback.
                $result.Reason = "KB page fetch failed or empty; will try update-history pages for KB."
            }

            # ------------ Fallback Method: Scan all update history pages for the KB ------------
            foreach ($sv in $historyPages.Keys) {
                $page = Get-PageContent -Url $historyPages[$sv]
                if (-not $page) { continue }
                # Use a broad regex to find sections containing patch date, KB, and build number.
                $matches = [regex]::Matches($page, $pagePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
                foreach ($m in $matches) {
                    # If we find a match for our specific KB number...
                    if ($m.Groups['KB'].Value -ieq $KBNumber) {
                        # ...populate the result object and return immediately.
                        $result.Found = $true
                        $result.KBNumber = $m.Groups['KB'].Value
                        $result.OSBuild = $m.Groups['BuildNumber'].Value
                        $result.PatchDate = $m.Groups['PatchDate'].Value
                        $result.ServerVersion = $sv
                        $result.SourceUsed = "HistoryPage:$sv"
                        $result.OutOfBand = if ([string]::IsNullOrWhiteSpace($m.Groups['OutOfBand'].Value)) { $false } else { $true }

                        return $result
                    }
                }
            }

            # If no information was found after all attempts.
            if (-not $result.Found) {
                if (-not $result.Reason) { $result.Reason = "No info found for $KBNumber on KB page or history pages." }
                return $result
            }
        }

        # --- LOGIC BRANCH: Search by Build Number ---
        elseif ($PSCmdlet.ParameterSetName -eq 'ByBuild') {
            # Normalize the build number to "major.minor" format (e.g., 17763.2237).
            $parts = $BuildNumber -split '\.'
            $normalized = if ($parts.Length -ge 2) { "$($parts[0]).$($parts[1])" } else { $BuildNumber }
            $major = $parts[0]

            # Determine the server version from the major build number.
            $serverKey = if ($osMap.ContainsKey($major)) { $osMap[$major] }

            if (-not $serverKey) {
                $result.Reason = "Unknown major build number '$major'; will try scanning all history pages."
            }

            # ------------ Primary Method: Scan the mapped history page for the build ------------
            $page = Get-PageContent -Url $historyPages[$serverKey]
            if ($page) {
                $matches = [regex]::Matches($page, $pagePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
                foreach ($m in $matches) {
                    $pageParts = ($m.Groups['BuildNumber'].Value) -split '\.'
                    $pageNormalized = if ($pageParts.Length -ge 2) { "$($pageParts[0]).$($pageParts[1])" } else { $m.Groups['BuildNumber'].Value }
                    # If it matches our target build number...
                    if ($pageNormalized -eq $normalized) {
                        $result.Found = $true
                        $result.KBNumber = $m.Groups['KB'].Value
                        $result.OSBuild = $m.Groups['BuildNumber'].Value
                        $result.PatchDate = $m.Groups['PatchDate'].Value
                        $result.ServerVersion = $serverKey
                        $result.SourceUsed = "HistoryPage:$serverKey"
                        $result.OutOfBand = if ([string]::IsNullOrWhiteSpace($m.Groups['OutOfBand'].Value)) { $false } else { $true }

                        if (-not $result.PatchDate -or -not $result.KBNumber) { break }  # Data is incomplete, go to fallback.
                        return $result
                    }
                }
            } else {
                $result.Reason = "Failed to download update-history for $serverKey; will try scanning other history pages."
            }

            # ------------ Fallback Method: Scan all history pages to find the build ------------
            foreach ($sv in $historyPages.Keys) {
                $page = Get-PageContent -Url $historyPages[$sv]
                if (-not $page) { continue }
                $matches = [regex]::Matches($page, $pagePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
                foreach ($m in $matches) {
                    $pageParts = ($m.Groups['BuildNumber'].Value) -split '\.'
                    $pageNormalized = if ($pageParts.Length -ge 2) { "$($pageParts[0]).$($pageParts[1])" } else { $m.Groups['BuildNumber'].Value }
                    if ($pageNormalized -eq $normalized) {
                        $result.Found = $true
                        $result.KBNumber = $m.Groups['KB'].Value
                        $result.OSBuild = $m.Groups['BuildNumber'].Value
                        $result.PatchDate = $m.Groups['PatchDate'].Value
                        $result.ServerVersion = $sv
                        $result.SourceUsed = "HistoryPage:$sv"
                        $result.OutOfBand = if ([string]::IsNullOrWhiteSpace($m.Groups['OutOfBand'].Value)) { $false } else { $true }
                        return $result
                    }
                }
            }

            # If no match was found after all attempts.
            if (-not $result.Found) {
                $result.Reason = "No matching CU found for normalized build $normalized."
                return $result
            }
        }

        else {
            # Handle cases where the function is called with an invalid parameter set.
            return [PSCustomObject]@{ Found = $false; Reason = "Invalid parameter set." }
        }
    } catch {
        # Catch any unexpected exceptions during the process.
        return [PSCustomObject]@{ Found = $false; Reason = "Exception: $($_.Exception.Message)" }
    }
}

function Get-PatchTuesday {
    <#
    .SYNOPSIS
        Calculates the Patch Tuesday date for a specific patch cycle.

    .DESCRIPTION
        Determines the Patch Tuesday corresponding to either the latest active patch cycle
        or a specific reference month.

        When -Latest is specified, the function evaluates the current date and returns the
        Patch Tuesday that represents the active patch cycle. If today's date is before the
        current month's Patch Tuesday, the previous month's Patch Tuesday is returned.

        When -ReferenceMonth is specified, the function returns the Patch Tuesday for the
        provided month, regardless of the current date.

        Exactly one parameter must be specified. The parameters are mutually exclusive.
    .OUTPUTS
        [pscustomobject] An object containing the date of the relevant Patch Tuesday.
    #>

    # Get the first day of the current month.
    [CmdletBinding(DefaultParameterSetName='Latest')]
    param (
        [Parameter(Mandatory=$false, ParameterSetName='Latest')]
        [switch]$Latest,

        [Parameter(Mandatory=$true, ParameterSetName='Reference')]
        [datetime]$ReferenceMonth
    )

    if ($ReferenceMonth) {
        $firstDay = Get-Date $ReferenceMonth -Day 1
        $patchTuesday = Get-Date (Get-SecondTuesday -Date $firstDay) -Hour 19 -Minute 0 -Second 0 -Millisecond 0

        if (((Get-Date).ToShortDateString() -replace '-\d\d$') -eq ($patchTuesday.ToShortDateString() -replace '-\d\d$')) {
            $ThisMonth = $true
        } else {
            $ThisMonth = $false
        }
    } else {
        $firstDay = Get-Date -Day 1
        $patchTuesday = Get-Date (Get-SecondTuesday -Date $firstDay) -Hour 19 -Minute 0 -Second 0 -Millisecond 0
        $ThisMonth = $true

        # If today is before this month's Patch Tuesday, the latest cycle is last month's.
        if ((Get-Date) -lt $patchTuesday) {
            $firstDay = $firstDay.AddMonths(-1)
            $patchTuesday = Get-Date (Get-SecondTuesday -Date $firstDay) -Hour 19 -Minute 0 -Second 0 -Millisecond 0
            $ThisMonth = $false
        }
    }

    return [PSCustomObject]@{
        Date = [DateTime]$patchTuesday # The date of the relevant Patch Tuesday.
        ThisMonth = $ThisMonth # Flag indicating if the cycle is for the current calendar month.
    }
}


function Get-LatestWuaPatch {
    <#
    .SYNOPSIS
        Gets the latest installed cumulative update using the Windows Update Agent (WUA) API.
    .DESCRIPTION
        This function queries the WUA history for installed, non-preview cumulative updates,
        sorts them, and returns structured information about the most recent one. It attempts
        to determine the patch month from the title, and if that fails, it falls back to
        online lookup or estimation based on install date.
    .OUTPUTS
        [pscustomobject] An object containing details of the latest patch found via WUA.
    #>
    [CmdletBinding()]
    param()

    try {
        # --- Initialize WUA session ---
        # Create a COM object to interact with the Windows Update Agent API.
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()

        if ($historyCount -eq 0) {
            return [pscustomobject]@{
                Reason = "No update history found."
            }
        }

        # Query the full update history and filter for relevant updates:
        # - Operation 1 means 'Installation'.
        # - Title must indicate a security or out-of-band update with a date prefix, or must match a cumulative update for Windows Server.
        # - Title must not contain "Preview".
        $rgx1 = "^(?:(?:\d{4}-\d{2}|\d{2}-\d{4})\s*(?:-|\u2013|\u2014|:)?\s*(?:Security Update |Säkerhetsuppdatering |Out-of-Band |Out of Band )|(?:Security Update |Säkerhetsuppdatering |Out-of-Band |Out of Band ))"
        $historyFiltered = $searcher.QueryHistory(0, $historyCount) |
            Where-Object {
                $_.Operation -eq 1 -and
                ($_.Title -match $rgx1 -or
                $_.Title -match "(Cumulative Update for|Kumulativ uppdatering för) (Microsoft|Windows) Server") -and
                $_.Title -notmatch "Preview"
            }

        if (-not $historyFiltered -or $historyFiltered.Count -eq 0) {
            return [pscustomobject]@{
                Reason = "No cumulative update history found. ($historyCount total installed updates found)"
            }
        }

        # Convert the raw WUA history objects into structured custom objects.
        $cuHistory = $historyFiltered | ForEach-Object {
            [pscustomobject]@{
                InstallDate    = [DateTime]$_.Date
                Title          = $_.Title
                KBs            = (Get-KBsFromTitle -title $_.Title) -join ', '
                PatchYearMonth = Get-PatchYearMonthFromTitle -title $_.Title # Extract YYYY-MM if possible
            }
        }

        # Evaluate how to sort list
        $sortProperty = if($_.PatchYearMonth){"PatchYearMonth"}else{"InstallDate"}


        # The latest patch is the first one after sorting.
        $latestPatch = $cuHistory | Sort-Object $sortProperty -Descending | Select-Object -First 1

        # Determine the official patch month date (Patch Tuesday).
        # 1. Prefer the date from the title (most reliable).
        if ($latestPatch.PatchYearMonth) {
            $latestPatchDate = ([DateTime]$latestPatch.PatchYearMonth)
            $latestPatch | Add-Member -MemberType NoteProperty -Name CheckMethod -Value "Title" -Force
        # 2. If no date in title, look up the KB online.
        } elseif ($latestPatch.KBs) {
            foreach ($item in ($latestPatch.KBs -split ',\s*')) {
                if(($patchOnlineInfo = Get-MsftPatchInfo -KBNumber $item -ErrorAction SilentlyContinue).patchDate) {
                    $latestPatchDate = [DateTime]$patchOnlineInfo.PatchDate
                    $latestPatch | Add-Member -MemberType NoteProperty -Name CheckMethod -Value "Online" -Force
                    break
                }
            }
        }

        # 3. If online lookup fails, estimate the patch month based on the install date.
        if (-not $latestPatchDate) {
            # Find the Patch Tuesday of the month it was installed.
            $relativePatchTuesday = Get-SecondTuesday -Date $latestPatch.InstallDate

            # If installed on or after that month's Patch Tuesday, it belongs to that month.
            if ($latestPatch.InstallDate -ge $relativePatchTuesday) {
                $latestPatchDate = (Get-Date $relativePatchTuesday -Day 1)
            # Otherwise, it belongs to the previous month's patch cycle.
            } else {
                $latestPatchDate = (Get-Date $relativePatchTuesday -Day 1).AddMonths(-1)
            }

            $latestPatch | Add-Member -MemberType NoteProperty -Name CheckMethod -Value "InstallDate" -Force

        }

        # Determine if the patch is out-of-band based on title content.
        if ( $latestPatch.Title -match $rgx1 ) {
            $patchOnlineInfo = Get-MsftPatchInfo -KBNumber ($latestPatch.KBs -split ',\s*')[0] -ErrorAction SilentlyContinue

            if ($patchOnlineInfo.Found -and $patchOnlineInfo.OutOfBand -eq $true) {
                $outOfBand = $true
                $updateType = "Out-of-Band Security Update"
                $latestPatch.CheckMethod = "Online"
            } elseif ($patchOnlineInfo.Found -eq $false) {
                $outOfBand = "UNKNOWN"
                $updateType = "Security Update"
            } else {
                $outOfBand = $false
                $updateType = "Security Update"
                $latestPatch.CheckMethod = "Online"
            }
        } else {
            $outOfBand = $false
            $updateType = "Cumulative Update"
        }

        $latestPatch | Add-Member -MemberType NoteProperty -Name OutOfBand -Value $outOfBand -Force
        $latestPatch | Add-Member -MemberType NoteProperty -Name UpdateType -Value $updateType -Force

        return [pscustomobject]@{
            LatestPatch = $latestPatch # The structured object for the latest patch.
            LatestPatchMonth = [DateTime]($latestPatchDate.ToShortDateString()) # The calculated patch cycle date.
        }

    } catch {
        # Return an error object if any part of the WUA interaction fails.
        return [pscustomobject]@{
            Reason = "UNKNOWN: Exception occurred - $($_.Exception.Message)"
        }
    }
}


function Get-LatestDismPackage {
    <#
    .SYNOPSIS
        Gets the latest installed cumulative update package using DISM.
    .DESCRIPTION
        This function serves as a fallback when the WUA API is unavailable. It parses
        the output of 'dism /get-packages' to find "RollupFix" packages, which
        correspond to cumulative updates. It then sorts them by install time to find

        the latest one and attempts to enrich the data with online lookups.
    .OUTPUTS
        [pscustomobject] An object containing details of the latest patch found via DISM.
    #>

    # Query DISM for all installed packages and capture the output as a string.
    $dismOutput = dism /online /get-packages /english | Out-String

    # Split the output into blocks, with each block representing one package.
    $packages = $dismOutput -split "(?m)^Package Identity"

    # Process each package block to extract relevant information.
    $cuPackages = foreach ($pkg in $packages) {
        # Filter for cumulative updates ("RollupFix").
        if ($pkg -match "Package_for_RollupFix") {
            # Use regex to extract state, install time, and package identity.
            $state = if ($pkg -match "State\s*:\s*(.+)") { $matches[1].Trim() } else { $null }
            $installTime = if ($pkg -match "Install Time\s*:\s*(.+)") { if($matches[1].Trim()) { [datetime]$matches[1] } } else { $null }
            $identity = if ($pkg -match "(Package_for_RollupFix[^\r\n]*)") { $matches[1] } else { $null }
            $build = if ($identity -match "~~(.+)$") { $matches[1] } else { $null }

            if (-not $installTime) { continue } # Skip if install time is missing.

            # Estimate the patch month based on install time (same logic as in WUA function).
            $relativePatchTuesday = Get-SecondTuesday -Date $installTime
            if ($installTime -ge $relativePatchTuesday) {
                $latestPatchDate = (Get-Date $relativePatchTuesday -Day 1)
            } else {
                $latestPatchDate = (Get-Date $relativePatchTuesday -Day 1).AddMonths(-1)
            }

            [pscustomobject]@{
                PackageName     = $identity
                BuildNumber     = $build
                State           = $state
                InstallTime     = [DateTime]$installTime
            }
        }
    }

    # Sort the found cumulative updates by install time and get the most recent one.
    $latestCU = $cuPackages | Sort-Object InstallTime -Descending | Select-Object -First 1

    if ($latestCU) {
        # Attempt to find the KB number and server version by looking up the build number online.
        if(($patchOnlineInfo = Get-MsftPatchInfo -BuildNumber $latestCU.BuildNumber -ErrorAction SilentlyContinue).PatchDate) {
            $latestCU | Add-Member -MemberType NoteProperty -Name KBNumber -Value $patchOnlineInfo.KBNumber -Force
            $latestCU | Add-Member -MemberType NoteProperty -Name ServerVersion -Value $patchOnlineInfo.ServerVersion -Force
            $latestCU | Add-Member -MemberType NoteProperty -Name CheckMethod -Value "Online" -Force
            $latestCU | Add-Member -MemberType NoteProperty -Name OutOfBand -Value $patchOnlineInfo.OutOfBand -Force
            if ($patchOnlineInfo.OutOfBand -eq $true) {
                $latestCU | Add-Member -MemberType NoteProperty -Name UpdateType -Value "Out-of-Band Security Update" -Force
            } elseif ($patchOnlineInfo.OutOfBand -eq $false) {
                $latestCU | Add-Member -MemberType NoteProperty -Name UpdateType -Value "Cumulative Update" -Force
            }
            else {
                $latestCU | Add-Member -MemberType NoteProperty -Name UpdateType -Value "Unknown Update" -Force
            }
        } else {
            $latestCU | Add-Member -MemberType NoteProperty -Name CheckMethod -Value "InstallDate" -Force
            $latestCU | Add-Member -MemberType NoteProperty -Name OutOfBand -Value "UNKNOWN" -Force
            $latestCU | Add-Member -MemberType NoteProperty -Name UpdateType -Value "Unknown Update" -Force
        }

        # Add the calculated patch month to the final object. Use online date if available, otherwise the estimated one.
        $latestCU | Add-Member -MemberType NoteProperty -Name LatestPatchMonth -Value $( if ($patchOnlineInfo.PatchDate) { [DateTime](([DateTime]$patchOnlineInfo.PatchDate).ToShortDateString()) } else { [DateTime]($latestCU.InstallTime.ToShortDateString()) } ) -Force
    } else {
        # If no cumulative updates were found, return an error object.
        $latestCU = [pscustomobject]@{
            Reason = "No cumulative update packages found via DISM."
        }
    }

    return $latestCU

}

function Check-WindowsOsVersion {
    <#
    .SYNOPSIS
        Checks if the operating system is Windows Server 2016 or later.
    .DESCRIPTION
        This function retrieves the OS build number and verifies if it meets the minimum
        requirement for Windows Server 2016 (build 17763) or later.
    .OUTPUTS
        [bool] $true if the OS is supported, otherwise $false.
    #>
    param (
        [Int]$osBuild = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    )

    if ($osBuild -ge 14393) {
        return $true
    } else {
        return $false
    }
}

try {

    # --- Main Execution Logic ---

    # Check if the OS version is supported (Windows Server 2016 / build 17763 or later).
    if (-not (Check-WindowsOsVersion)) {
        Write-Output "N/A - Unsupported OS version. This script supports Windows Server 2016 and later."
        exit 0
    }

    # Check if the WUA (Windows Update Agent) service is available and running.
    if ((Test-WuaPrerequisites).CanUseWuaCom) {
        # If WUA is available, use it as the primary method to find the latest patch.
        $latestWuaPatch = Get-LatestWuaPatch
        if ($latestWuaPatch.LatestPatch) {
            # Extract the key details from the WUA result object.
            $latestPatchMonth = $latestWuaPatch.LatestPatchMonth
            $latestWuaPatch = $latestWuaPatch.LatestPatch
            $installdateFormated = (Get-Date $latestWuaPatch.InstallDate -Format "yyyy-MM-dd HH:mm")
            $latestKb = if ($latestWuaPatch.KBs) { $latestWuaPatch.KBs } else { $null }
            $usedMethod = "WUA"
        }
    }

    # If the WUA method failed or was skipped, use DISM as a fallback. Also if WUA matched a Security Update or Out-of-Band update, double check with DISM.
    if ((-not $latestWuaPatch.Title) -or ($latestWuaPatch.OutOfBand)) {
        $latestDismPatch = Get-LatestDismPackage

        if ((-not $latestDismPatch.InstallTime) -and (-not $latestWuaPatch.InstallDate)) {
            Write-Output "UNKNOWN - Failed to get expected result fromWUA or DISM."
            exit 0
        }

        $installTimeDiff = $false
        if ($latestWuaPatch.InstallDate -and $latestDismPatch.InstallTime) {
            if ([Math]::Abs((New-TimeSpan -Start $latestWuaPatch.InstallDate -End $latestDismPatch.InstallTime).TotalHours) -gt 1) {
                $installTimeDiff = $true
            }
        }

        # If WUA method did not produce a result or KB numbers from WUA and DISM doesn't match up. Continue with DISM-method
        if ((-not $latestWuaPatch.KBs) -or (($latestDismPatch.KBNumber) -and $latestDismPatch.KBNumber -notmatch $latestWuaPatch.KBs) -or ($installTimeDiff)) {
            if ($latestDismPatch.Reason) {
                if (-not $latestWuaPatch.Title) {
                    Write-Output "OK - No installed Cumulative Updates found. WUA Reason: $($latestWuaPatch.Reason); DISM Reason: $($latestDismPatch.Reason)"
                    exit 0
                }
            } else {
                # Extract the key details from the DISM result object.
                $latestPatchMonth = $latestDismPatch.LatestPatchMonth
                $installdateFormated = (Get-Date $latestDismPatch.InstallTime -Format "yyyy-MM-dd HH:mm")
                $latestKb = if ($latestDismPatch.KBNumber) { $latestDismPatch.KBNumber } else { $latestDismPatch.BuildNumber }

                if ($latestWuaPatch.OutOfBand -and (-not $installTimeDiff)) {
                    $usedMethod = "WUA"
                } else {
                    $usedMethod = "DISM"
                }
            }
        }
    }

    # Format the patch month for the output message (e.g., "October-2025").
    $enCulture = [System.Globalization.CultureInfo]::InvariantCulture  # Use invariant culture for consistent month names.
    $patchMonthYearName = (Get-Date $latestPatchMonth).ToString("MMMM-yyyy", $enCulture)


    # Determine the date of the current patch cycle's Patch Tuesday.
    $patchTuesdayRef = Get-PatchTuesday -Latest
    $patchTuesdayRefMonth = (Get-Date $patchTuesdayRef.Date.ToShortDateString() -Day 1)

    # Determine the reference month offset for status calculation.
    if ($patchTuesdayRef.ThisMonth) {
        # If the latest cycle is this month, the offset is 0.
        $refMonth = 0
    } else {
        # If the latest cycle was last month, the offset is 1.
        $refMonth = 1
    }


    # --- Status Evaluation ---
    # Compare the installed patch month against the current and previous patch cycles or against custom thresholds.

    if ($useCustomThresholds) {

        # Determine the Patch Tuesday for the next patch cycle after the installed patch month instead of the latest patch tuesday.
        $patchTuesdayRef = Get-PatchTuesday -ReferenceMonth $latestPatchMonth.AddMonths(1)
        $patchTuesdayRefMonth = (Get-Date $patchTuesdayRef.Date.ToShortDateString() -Day 1)

        # Check if the current patch cycle's patch is installed
        $isPatchInstalled = $latestPatchMonth -ge $patchTuesdayRefMonth

        # If not installed, double check with DISM if a newer patch is detected
        if (-not $isPatchInstalled) {
            if (-not $latestDismPatch) {
                $latestDismPatch = Get-LatestDismPackage

                # If DISM finds a newer patch, update all relevant variables
                if ($latestDismPatch.LatestPatchMonth -ge $patchTuesdayRefMonth) {
                    $isPatchInstalled = $true
                    $latestPatchMonth = $latestDismPatch.LatestPatchMonth
                    $installdateFormated = (Get-Date $latestDismPatch.InstallTime -Format "yyyy-MM-dd HH:mm")
                    $latestKb = if ($latestDismPatch.KBNumber) { $latestDismPatch.KBNumber } else { $latestDismPatch.BuildNumber }
                    $patchMonthYearName = (Get-Date $latestPatchMonth).ToString("MMMM-yyyy", $enCulture)
                    $usedMethod = "DISM"

                    $patchTuesdayRef = Get-PatchTuesday -ReferenceMonth $latestPatchMonth.AddMonths(1)
                    $patchTuesdayRefMonth = (Get-Date $patchTuesdayRef.Date.ToShortDateString() -Day 1)
                }
            }
        }

        # Calculate days since Patch Tuesday and deadlines
        $daysSincePatchTuesday = (New-TimeSpan -Start $patchTuesdayRef.Date.ToShortDateString() -End (Get-Date).ToShortDateString()).Days
        $warningDeadline = (Get-Date $patchTuesdayRef.Date.ToShortDateString()).AddDays($WarningDaysAfterPatchTuesday)
        $criticalDeadline = (Get-Date $patchTuesdayRef.Date.ToShortDateString()).AddDays($CriticalDaysAfterPatchTuesday)

        # Format the patch month for the output message (e.g., "October-2025").
        $patchTuesdayMonthYearName = (Get-Date $patchTuesdayRefMonth).ToString("MMMM-yyyy", $enCulture)

        # OK if patch is installed OR we haven't reached warning deadline yet
        if ($isPatchInstalled -or ((Get-Date) -lt $warningDeadline)) {
            $statusPrefix = if( $usedMethod -eq "WUA" ) { $latestWuaPatch.UpdateType } elseif ( $usedMethod -eq "DISM" ) { $latestDismPatch.UpdateType }
            $status = "OK - $statusPrefix $patchMonthYearName patch $("($latestKb) ")- InstallDate: $installdateFormated (via $(if ($usedMethod -match "WUA") { "WUA-$($latestWuaPatch.CheckMethod)" } else { "DISM-$($latestDismPatch.CheckMethod)" }))"
            $code = 0
        }

        # WARNING if patch is NOT installed AND critical deadline has not yet passed
        elseif ((-not $isPatchInstalled) -and (Get-Date) -lt $criticalDeadline) {
            $statusPrefix = if( $usedMethod -eq "WUA" ) { $latestWuaPatch.UpdateType } elseif ( $usedMethod -eq "DISM" ) { $latestDismPatch.UpdateType }
            $status = "WARNING - $daysSincePatchTuesday days behind Patch Tuesday for $patchTuesdayMonthYearName - InstalledPatch: $statusPrefix $patchMonthYearName $("($latestKb) ")- InstallDate: $installdateFormated (via $(if ($usedMethod -match "WUA") { "WUA-$($latestWuaPatch.CheckMethod)" } else { "DISM-$($latestDismPatch.CheckMethod)" }))"
            $code = 1
        }

        # CRITICAL if patch NOT installed AND critical deadline has passed
        elseif ((-not $isPatchInstalled) -and (Get-Date) -ge $criticalDeadline) {
            $statusPrefix = if( $usedMethod -eq "WUA" ) { $latestWuaPatch.UpdateType } elseif ( $usedMethod -eq "DISM" ) { $latestDismPatch.UpdateType }
            $status = "CRITICAL - $daysSincePatchTuesday days behind Patch Tuesday for $patchTuesdayMonthYearName - InstalledPatch: $statusPrefix $patchMonthYearName $("($latestKb) ")- InstallDate: $installdateFormated (via $(if ($usedMethod -match "WUA") { "WUA-$($latestWuaPatch.CheckMethod)" } else { "DISM-$($latestDismPatch.CheckMethod)" }))"
            $code = 2
        }

        # UNKNOWN: A condition was met that doesn't fit OK, WARNING, or CRITICAL logic.
        else {
            $status = "Unable to determine patch status"
            $code = 0 # Defaulting to OK to avoid false alerts.
        }

    } else {

        # OK: The installed patch is from the current or previous cycle, making it up-to-date.
        if ($latestPatchMonth -ge $patchTuesdayRefMonth.AddMonths($refMonth-1)) {
                $statusPrefix = if( $usedMethod -eq "WUA" ) { $latestWuaPatch.UpdateType } elseif ( $usedMethod -eq "DISM" ) { $latestDismPatch.UpdateType }
                $status = "OK - $statusPrefix $patchMonthYearName patch $("($latestKb) ")- InstallDate: $installdateFormated (via $(if ($usedMethod -match "WUA") { "WUA-$($latestWuaPatch.CheckMethod)" } else { "DISM-$($latestDismPatch.CheckMethod)" }))"
                $code = 0
        }


        # WARNING: The installed patch is one month behind the required cycle.
        elseif ($latestPatchMonth -ge $patchTuesdayRefMonth.AddMonths($refMonth-2)) {
            # If the primary WUA check resulted in a WARNING, re-check with DISM.
            # This handles cases where WUA history might be stale or incomplete.
            if (!$latestDismPatch) {
                $latestDismPatch = Get-LatestDismPackage

                # If DISM finds a newer patch that is OK, override the WUA status.
                if ($latestDismPatch.latestPatchMonth -ge $patchTuesdayRefMonth.AddMonths($refMonth-1)) {
                    $latestPatchMonth = $latestDismPatch.LatestPatchMonth
                    $installdateFormated = (Get-Date $latestDismPatch.InstallTime -Format "yyyy-MM-dd HH:mm")
                    $latestKb = if ($latestDismPatch.KBNumber) { $latestDismPatch.KBNumber } else { $latestDismPatch.BuildNumber }
                    $patchMonthYearName = (Get-Date $latestPatchMonth).ToString("MMMM-yyyy", $enCulture)

                    $status = "OK - $($latestDismPatch.UpdateType) $patchMonthYearName patch $("($latestKb) ")- InstallDate: $installdateFormated (via DISM-$($latestDismPatch.CheckMethod))"
                    $code = 0
                }
            }

            # If after the re-check the status is still not OK, set to WARNING.
            if ($latestDismPatch) {
                $statusPrefix = if( $usedMethod -eq "WUA" ) { $latestWuaPatch.UpdateType } elseif ( $usedMethod -eq "DISM" ) { $latestDismPatch.UpdateType }
                $status = "WARNING - One month behind - InstalledPatch: $statusPrefix $patchMonthYearName $("($latestKb) ")- InstallDate: $installdateFormated (via $(if ($usedMethod -match "WUA") { "WUA-$($latestWuaPatch.CheckMethod)" } else { "DISM-$($latestDismPatch.CheckMethod)" }))"
                $code = 1
            }
        }


        # CRITICAL: The installed patch is two or more months behind.
        elseif ($latestPatchMonth -le $patchTuesdayRefMonth.AddMonths($refMonth-3)) {
            # Re-check with DISM to ensure the WUA data wasn't stale.
            if (!$latestDismPatch) {
                $latestDismPatch = Get-LatestDismPackage

                # If DISM finds a newer patch, re-evaluate its status.
                if ($latestDismPatch.latestPatchMonth -ge $patchTuesdayRefMonth.AddMonths($refMonth-2)) {
                    $latestPatchMonth = $latestDismPatch.LatestPatchMonth
                    $installdateFormated = (Get-Date $latestDismPatch.InstallTime -Format "yyyy-MM-dd HH:mm")
                    $latestKb = if ($latestDismPatch.KBNumber) { $latestDismPatch.KBNumber } else { $latestDismPatch.BuildNumber }
                    $patchMonthYearName = (Get-Date $latestPatchMonth).ToString("MMMM-yyyy", $enCulture)

                    if ($latestDismPatch.latestPatchMonth -ge $patchTuesdayRefMonth.AddMonths($refMonth-1)) {
                        # DISM found a patch that is OK.
                        $status = "OK - $($latestDismPatch.UpdateType) $patchMonthYearName patch $("($latestKb) ")- InstallDate: $installdateFormated (via DISM-$($latestDismPatch.CheckMethod))"
                        $code = 0
                    } else {
                        # DISM found a patch that is only a WARNING.
                        $status = "WARNING - One month behind - InstalledPatch: $($latestDismPatch.UpdateType) $patchMonthYearName $("($latestKb) ")- InstallDate: $installdateFormated (via DISM-$($latestDismPatch.CheckMethod))"
                        $code = 1
                    }
                }
            }

            # If after the re-check the status is still CRITICAL.
            if ($latestDismPatch) {
                $statusPrefix = if( $usedMethod -eq "WUA" ) { $latestWuaPatch.UpdateType } elseif ( $usedMethod -eq "DISM" ) { $latestDismPatch.UpdateType }
                $status = "CRITICAL - Two or more months behind - InstalledPatch: $statusPrefix $patchMonthYearName $("($latestKb) ")- InstallDate: $installdateFormated (via $(if ($usedMethod -match "WUA") { "WUA-$($latestWuaPatch.CheckMethod)" } else { "DISM-$($latestDismPatch.CheckMethod)" }))"
                $code = 2
            }
        }
        else {
            # UNKNOWN: A condition was met that doesn't fit OK, WARNING, or CRITICAL logic.
            $status = "Unable to determine patch status"
            $code = 0 # Defaulting to OK to avoid false alerts.
        }
    }

    # --- Output and Exit ---
    # Print the final status message to standard output.
    Write-Output $status
    # Exit with the appropriate Nagios-compatible status code.
    exit $code

} catch {
    # Global catch block for any unhandled exceptions in the main script body.
    Write-Output "Exception occurred - $($_.Exception.Message)"
    exit 0 # Exit with OK to prevent false CRITICAL alerts in monitoring.
}