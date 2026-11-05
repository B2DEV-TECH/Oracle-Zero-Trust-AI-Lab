# M1 / G0 - clean shutdown of one local instance.
# Usage: powershell -File stop-instance.ps1 -Name lab -Root <lab folder>
param(
    [Parameter(Mandatory)] [ValidatePattern('^[a-z]+$')] [string] $Name,
    [Parameter(Mandatory)] [string] $Root,
    [string] $Server = 'mysql-commercial-26.7.0-winx64'
)
$ErrorActionPreference = 'Stop'
$mysqladmin = Join-Path $Root "server\$Server\bin\mysqladmin.exe"
& $mysqladmin "--defaults-extra-file=$(Join-Path $Root "secrets\$Name-root.cnf")" shutdown
if ($LASTEXITCODE -ne 0) { throw "shutdown of '$Name' failed (exit $LASTEXITCODE)" }
"INSTANCE_${Name}_STOPPED"
