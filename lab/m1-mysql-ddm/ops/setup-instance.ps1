# M1 / G0 - create and initialize one local MySQL Enterprise instance (no Windows service).
#
# Usage:   powershell -File setup-instance.ps1 -Name lab -Port <port> -Root <lab folder>
#          powershell -File setup-instance.ps1 -Name shadow -Port <another port> -Root <lab folder>
#          <lab folder>\server\<Server> holds the unpacked MySQL Enterprise Server ZIP.
#
# Effects: creates <root>\instances\<name>\ (my.ini, data, files, tmp),
#          initializes the data directory with --initialize (random root password),
#          starts mysqld as a background process bound to 127.0.0.1 only,
#          replaces the expired root password with a new random one and writes
#          a client option file to <root>\secrets\<name>-root.cnf.
# Reverted by: stop-instance.ps1, then deleting <root>\instances\<name> and the secret file.
# Never prints a password.

param(
    [Parameter(Mandatory)] [ValidatePattern('^[a-z]+$')] [string] $Name,
    [Parameter(Mandatory)] [ValidateRange(1024, 65535)] [int] $Port,
    [Parameter(Mandatory)] [string] $Root,
    [string] $Server = 'mysql-commercial-26.7.0-winx64'
)
$ErrorActionPreference = 'Stop'

$base    = Join-Path $Root "server\$Server"
$inst    = Join-Path $Root "instances\$Name"
$secrets = Join-Path $Root 'secrets'
$mysqld  = Join-Path $base 'bin\mysqld.exe'
$mysql   = Join-Path $base 'bin\mysql.exe'

if (Test-Path (Join-Path $inst 'data')) { throw "Instance '$Name' already has a data directory. Aborting." }
$busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
if ($busy) { throw "Port $Port is already in use. Aborting." }

New-Item -ItemType Directory -Force $inst, (Join-Path $inst 'files'), (Join-Path $inst 'tmp'), $secrets | Out-Null

# Option files are written as ASCII without BOM; forward slashes in paths.
function Write-Ascii([string] $Path, [string] $Text) {
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::ASCII)
}
$fw = { param($p) $p -replace '\\', '/' }

$myIni = @"
[mysqld]
basedir=$(& $fw $base)
datadir=$(& $fw (Join-Path $inst 'data'))
port=$Port
bind-address=127.0.0.1
mysqlx=OFF
log-error=$(& $fw (Join-Path $inst 'mysqld.err'))
pid-file=$(& $fw (Join-Path $inst 'mysqld.pid'))
tmpdir=$(& $fw (Join-Path $inst 'tmp'))
secure-file-priv=$(& $fw (Join-Path $inst 'files'))
"@
$iniPath = Join-Path $inst 'my.ini'
Write-Ascii $iniPath $myIni

# 1. Initialize (secure by default: random, expired root password printed to the console).
$initLog = Join-Path $inst 'initialize.log'
# Start-Process keeps native stderr out of the PowerShell error stream (PS 5.1 quirk).
$p = Start-Process -FilePath $mysqld -ArgumentList "--defaults-file=`"$iniPath`"", '--initialize', '--console' `
        -NoNewWindow -Wait -PassThru -RedirectStandardError $initLog -RedirectStandardOutput "$initLog.out"
if ($p.ExitCode -ne 0) { throw "mysqld --initialize failed (exit $($p.ExitCode)). See $initLog" }
$line = Select-String -Path $initLog -Pattern 'temporary password is generated for root@localhost: (\S+)' | Select-Object -First 1
if (-not $line) { throw "Temporary root password not found in $initLog" }
$tempPwd = $line.Matches[0].Groups[1].Value

# 2. Start mysqld in the background (console process, no service).
Start-Process -FilePath $mysqld -ArgumentList "--defaults-file=`"$iniPath`"" -WindowStyle Hidden | Out-Null
$deadline = (Get-Date).AddSeconds(90)
while (-not (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw "mysqld '$Name' did not start listening on $Port within 90 s. See mysqld.err" }
    Start-Sleep -Milliseconds 500
}

# 3. Replace the expired root password. Passwords go through option files and stdin, never argv.
$chars  = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
$rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes  = New-Object byte[] 28
$rng.GetBytes($bytes)
$newPwd = 'M1' + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))

$tmpCnf = Join-Path $secrets "$Name-root-initial.cnf"
Write-Ascii $tmpCnf "[client]`nuser=root`npassword=$tempPwd`nhost=127.0.0.1`nport=$Port`n"
"ALTER USER 'root'@'localhost' IDENTIFIED BY '$newPwd';" |
    & $mysql "--defaults-extra-file=$tmpCnf" --connect-expired-password --batch
$rc = $LASTEXITCODE
Remove-Item $tmpCnf -Force
if ($rc -ne 0) { throw "Root password change failed (exit $rc)" }

$rootCnf = Join-Path $secrets "$Name-root.cnf"
Write-Ascii $rootCnf "[client]`nuser=root`npassword=$newPwd`nhost=127.0.0.1`nport=$Port`n"

# 4. The temporary password in initialize.log is now invalid; redact it anyway.
(Get-Content $initLog) -replace '(temporary password is generated for root@localhost: )\S+', '$1<redacted>' |
    Set-Content -Path $initLog -Encoding ascii

& $mysql "--defaults-extra-file=$rootCnf" --batch -e "SELECT @@version, @@version_comment, @@port, @@bind_address;"
"INSTANCE_${Name}_READY"
