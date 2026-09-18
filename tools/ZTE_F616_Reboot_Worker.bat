@echo off
setlocal EnableExtensions
chcp 65001 >nul

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=[IO.File]::ReadAllText('%~f0');$m='#<'+'POWERSHELL>';$i=$p.IndexOf($m);if($i -lt 0){throw 'PowerShell marker not found'};Invoke-Expression $p.Substring($i+$m.Length)"
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" echo ZTE reboot failed. Error code: %RC%
exit /b %RC%

#<POWERSHELL>
$ErrorActionPreference = 'Stop'

$BaseUrl  = if ([string]::IsNullOrWhiteSpace($env:MWOIF_ROUTER_BASE_URL)) { 'https://192.168.1.1' } else { $env:MWOIF_ROUTER_BASE_URL.TrimEnd('/') }
$RouterIp = if ([string]::IsNullOrWhiteSpace($env:MWOIF_ROUTER_IP)) { '192.168.1.1' } else { $env:MWOIF_ROUTER_IP.Trim() }
$Cookie   = Join-Path $env:TEMP ("zte_f616_cookie_" + [guid]::NewGuid().ToString("N") + ".txt")

function Get-Sha256Hex {
    param([Parameter(Mandatory=$true)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash  = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-LoginValue {
    param(
        [Parameter(Mandatory=$true)][string]$Html,
        [Parameter(Mandatory=$true)][string]$Name
    )

    $esc = [regex]::Escape($Name)

    $patterns = @(
        "(?is)['""]$esc['""]\s*,\s*['""]([^'""]*)['""]",
        "(?is)<input\b[^>]*(?:name|id)\s*=\s*['""]$esc['""][^>]*value\s*=\s*['""]([^'""]*)['""]",
        "(?is)<input\b[^>]*value\s*=\s*['""]([^'""]*)['""][^>]*(?:name|id)\s*=\s*['""]$esc['""]"
    )

    foreach ($p in $patterns) {
        $m = [regex]::Match($Html, $p)
        if ($m.Success) {
            return [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
        }
    }

    return ''
}

function Get-Attr {
    param(
        [Parameter(Mandatory=$true)][string]$Tag,
        [Parameter(Mandatory=$true)][string]$Name
    )

    $esc = [regex]::Escape($Name)

    $m = [regex]::Match($Tag, "(?is)\b$esc\s*=\s*['""]([^'""]*)['""]")
    if ($m.Success) {
        return [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
    }

    $m = [regex]::Match($Tag, "(?is)\b$esc\s*=\s*([^\s>]+)")
    if ($m.Success) {
        return [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
    }

    return ''
}

function Get-RebootFormFields {
    param([Parameter(Mandatory=$true)][string]$Html)

    $form = [regex]::Match(
        $Html,
        '(?is)<form\b[^>]*(?:id|name)\s*=\s*(?:"fSubmit"|''fSubmit''|fSubmit)\b[^>]*>.*?</form>'
    )

    if (-not $form.Success) {
        throw "Could not find form 'fSubmit' on easySetup.ghtml."
    }

    $fields = [ordered]@{}

    foreach ($item in [regex]::Matches($form.Value, '(?is)<input\b[^>]*>')) {
        $tag = $item.Value

        $name = Get-Attr -Tag $tag -Name 'name'
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = Get-Attr -Tag $tag -Name 'id'
        }
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $type = (Get-Attr -Tag $tag -Name 'type').ToLowerInvariant()

        if ($type -in @('button','submit','reset','file','image')) {
            continue
        }

        if ($type -in @('checkbox','radio')) {
            if ($tag -notmatch '(?is)\bchecked(?:\s*=\s*(?:"checked"|''checked''|checked))?\b') {
                continue
            }
        }

        $value = Get-Attr -Tag $tag -Name 'value'

        if ([string]::IsNullOrEmpty($value)) {
            $escaped = [regex]::Escape($name)
            $jsPatterns = @(
                "(?is)setValue\s*\(\s*['""]$escaped['""]\s*,\s*['""]([^'""]*)['""]\s*\)",
                "(?is)getObj\s*\(\s*['""]$escaped['""]\s*\)\.value\s*=\s*['""]([^'""]*)['""]"
            )
            foreach ($p in $jsPatterns) {
                $m = [regex]::Match($Html, $p)
                if ($m.Success) {
                    $value = [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
                    break
                }
            }
        }

        if (($type -in @('checkbox','radio')) -and [string]::IsNullOrEmpty($value)) {
            $value = 'on'
        }

        $fields[$name] = $value
    }

    foreach ($item in [regex]::Matches($form.Value, '(?is)<select\b[^>]*>.*?</select>')) {
        $selectHtml = $item.Value
        $openTag = [regex]::Match($selectHtml, '(?is)^<select\b[^>]*>').Value

        $name = Get-Attr -Tag $openTag -Name 'name'
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = Get-Attr -Tag $openTag -Name 'id'
        }
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $options = [regex]::Matches($selectHtml, '(?is)<option\b[^>]*>.*?</option>')
        if ($options.Count -eq 0) {
            $fields[$name] = ''
            continue
        }

        $chosen = $null
        foreach ($opt in $options) {
            if ($opt.Value -match '(?is)\bselected(?:\s*=\s*(?:"selected"|''selected''|selected))?\b') {
                $chosen = $opt.Value
                break
            }
        }
        if ($null -eq $chosen) {
            $chosen = $options[0].Value
        }

        $optOpen = [regex]::Match($chosen, '(?is)^<option\b[^>]*>').Value
        $value = Get-Attr -Tag $optOpen -Name 'value'
        if ([string]::IsNullOrEmpty($value)) {
            $value = [regex]::Replace($chosen, '(?is)<[^>]+>', '')
            $value = [System.Net.WebUtility]::HtmlDecode($value).Trim()
        }

        $fields[$name] = $value
    }

    foreach ($item in [regex]::Matches($form.Value, '(?is)<textarea\b[^>]*>.*?</textarea>')) {
        $taHtml = $item.Value
        $openTag = [regex]::Match($taHtml, '(?is)^<textarea\b[^>]*>').Value

        $name = Get-Attr -Tag $openTag -Name 'name'
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = Get-Attr -Tag $openTag -Name 'id'
        }
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $value = [regex]::Replace($taHtml, '(?is)^<textarea\b[^>]*>|</textarea>$', '')
        $fields[$name] = [System.Net.WebUtility]::HtmlDecode($value)
    }

    $fields['IF_ACTION'] = 'reboot'

    return $fields
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $common = @(
        '-k',
        '--ssl-no-revoke',
        '--http1.1',
        '--connect-timeout', '6',
        '--max-time', '20',
        '-sS',
        '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36'
    )

    $output = & curl.exe @common @Arguments 2>&1
    $code = $LASTEXITCODE

    if (($code -ne 0) -and (-not $AllowFailure)) {
        $msg = ($output | Out-String).Trim()
        throw "curl.exe failed (code $code): $msg"
    }

    return [pscustomobject]@{
        Code = $code
        Text = ($output | Out-String)
    }
}

function Test-Tcp443 {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($RouterIp, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(700, $false)) {
            return $false
        }
        $client.EndConnect($ar)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Wait-RouterDown {
    param([int]$Seconds = 20)
    for ($i = 0; $i -lt $Seconds; $i++) {
        Start-Sleep -Seconds 1
        if (-not (Test-Tcp443)) {
            return $true
        }
    }
    return $false
}

function Wait-RouterUp {
    param([int]$Seconds = 180)
    for ($i = 0; $i -lt $Seconds; $i++) {
        if (Test-Tcp443) {
            return $true
        }
        if (($i % 10) -eq 0) {
            Write-Host "Waiting for router... $i/$Seconds sec"
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

Write-Host ''
Write-Host '=== M WOIF ZTE F616 Provider Recovery ==='
Write-Host 'Mode: non-interactive one-shot'
Write-Host ''

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    throw 'curl.exe was not found. Windows 10/11 normally includes it.'
}

$User = [string]$env:MWOIF_ROUTER_USERNAME
$Pass = [string]$env:MWOIF_ROUTER_PASSWORD
$Bstr = [IntPtr]::Zero
if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrEmpty($Pass)) {
    Write-Host 'ERROR: router credentials are not configured.'
    exit 3
}

try {

    Write-Host '[1/6] Testing HTTPS with curl.exe...'
    $test = Invoke-Curl -Arguments @(
        '-o', 'NUL',
        '-w', 'HTTP=%{http_code}',
        '-c', $Cookie,
        '-b', $Cookie,
        "$BaseUrl/"
    )
    Write-Host ('      ' + $test.Text.Trim())

    Write-Host '[2/6] Reading ZTE login page...'
    $loginPageResp = Invoke-Curl -Arguments @(
        '-c', $Cookie,
        '-b', $Cookie,
        "$BaseUrl/"
    )
    $html = $loginPageResp.Text

    $LoginToken = Get-LoginValue -Html $html -Name 'Frm_Logintoken'
    $LoginCheck = Get-LoginValue -Html $html -Name 'Frm_Loginchecktoken'

    if ([string]::IsNullOrWhiteSpace($LoginToken)) {
        throw 'Frm_Logintoken was not found. Firmware login page format differs.'
    }

    $Random = Get-Random -Minimum 10000000 -Maximum 99999999
    $Hash = Get-Sha256Hex ($Pass + $Random)

    Write-Host '[3/6] Logging in...'
    $loginArgs = @(
        '-c', $Cookie,
        '-b', $Cookie,
        '-e', "$BaseUrl/",
        '--data-urlencode', 'action=login',
        '--data-urlencode', ("Username=" + $User),
        '--data-urlencode', ("Password=" + $Hash),
        '--data-urlencode', ("Frm_Logintoken=" + $LoginToken),
        '--data-urlencode', ("UserRandomNum=" + $Random),
        '--data-urlencode', ("Frm_Loginchecktoken=" + $LoginCheck),
        "$BaseUrl/"
    )
    $null = Invoke-Curl -Arguments $loginArgs

    Write-Host '[4/6] Loading ZTE System Management page...'

    $ManagerPath = '/getpage.gch?pid=1002&nextpage=manager_dev_conf_t.gch'
    $manager = Invoke-Curl -Arguments @(
        '-c', $Cookie,
        '-b', $Cookie,
        '-e', "$BaseUrl/",
        ($BaseUrl + $ManagerPath)
    )
    $managerHtml = $manager.Text

    $tokenMatch = [regex]::Match(
        $managerHtml,
        '(?is)\bsession_token\s*=\s*["'']([^"'']+)["'']\s*;'
    )

    if (-not $tokenMatch.Success) {
        $template = Invoke-Curl -Arguments @(
            '-c', $Cookie,
            '-b', $Cookie,
            '-e', "$BaseUrl/",
            "$BaseUrl/template.gch"
        )

        $tokenMatch = [regex]::Match(
            $template.Text,
            '(?is)\bsession_token\s*=\s*["'']([^"'']+)["'']\s*;'
        )
    }

    if (-not $tokenMatch.Success) {
        throw 'Could not obtain ZTE session_token after login.'
    }

    $SessionToken = $tokenMatch.Groups[1].Value
    Write-Host '      Session token acquired.'

    Write-Host '[5/6] Sending direct system reboot command...'

    $rebootArgs = @(
        '-c', $Cookie,
        '-b', $Cookie,
        '-e', ($BaseUrl + $ManagerPath),
        '--data-urlencode', 'flag=1',
        '--data-urlencode', 'IF_ACTION=devrestart',
        '--data-urlencode', ("_SESSION_TOKEN=" + $SessionToken),
        ($BaseUrl + $ManagerPath)
    )

    $result = Invoke-Curl -Arguments $rebootArgs -AllowFailure

    if ($result.Code -ne 0) {
        Write-Host "      HTTPS dropped during reboot request (curl code $($result.Code))."
    }

    Write-Host '[6/6] Confirming router reboot...'

    $downWait = 45
    if ($env:MWOIF_ROUTER_DOWN_TIMEOUT_SECONDS -match '^\d+$') { $downWait = [Math]::Max(10, [Math]::Min(120, [int]$env:MWOIF_ROUTER_DOWN_TIMEOUT_SECONDS)) }
    if (-not (Wait-RouterDown -Seconds $downWait)) {
        Write-Host ''
        Write-Host 'Router stayed online after direct reboot request.'
        Write-Host 'The command reached the management endpoint but reboot was not confirmed.'
        exit 2
    }

    Write-Host '      Router went offline. Reboot confirmed.'
    Write-Host '      Waiting for ZTE F616 to return...'

    $upWait = 600
    if ($env:MWOIF_ROUTER_UP_TIMEOUT_SECONDS -match '^\d+$') { $upWait = [Math]::Max(60, [Math]::Min(1200, [int]$env:MWOIF_ROUTER_UP_TIMEOUT_SECONDS)) }
    if (-not (Wait-RouterUp -Seconds $upWait)) {
        throw "Router rebooted, but HTTPS did not return within $upWait seconds."
    }

    Write-Host ''
    Write-Host 'DONE - ZTE F616 rebooted and is online again.'
    exit 0
}
catch {
    Write-Host ''
    Write-Host 'ERROR:' $_.Exception.Message
    Write-Host ''
    Write-Host 'If the error contains curl code 35 or SEC_E_ALGORITHM_MISMATCH,'
    Write-Host 'send that exact line back to me; it means the firmware uses an old TLS/cipher.'
    exit 1
}
finally {
    Remove-Variable Pass -ErrorAction SilentlyContinue
    Remove-Variable User -ErrorAction SilentlyContinue
    Remove-Item $Cookie -Force -ErrorAction SilentlyContinue
}
