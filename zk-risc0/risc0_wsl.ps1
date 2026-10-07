param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("prove", "verify", "verify-server", "method-id")]
    [string]$Command
)

$ErrorActionPreference = "Stop"

function Convert-ToWslPath {
    param([string]$Path)

    if ($Path -match '^([A-Za-z]):\\(.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2].Replace('\', '/')
        return "/mnt/$drive/$rest"
    }
    return $Path.Replace('\', '/')
}

function Quote-Bash {
    param([string]$Value)
    return "'" + $Value.Replace("'", "'\''") + "'"
}

$workspace = Convert-ToWslPath (Resolve-Path $PSScriptRoot).Path
$bashCommand = "cd " + (Quote-Bash $workspace) + " && " +
    "if [ ! -x ./target/release/host ]; then cargo build --release -p host; fi && " +
    "exec ./target/release/host " + (Quote-Bash $Command)

& wsl.exe bash -lc $bashCommand
exit $LASTEXITCODE
