param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
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

$wslCwd = Convert-ToWslPath (Get-Location).Path
$quotedArgs = $RemainingArgs | ForEach-Object { Quote-Bash $_ }
$setupPath = 'export PATH="$HOME/.local/bin:$HOME/.starkup/bin:$HOME/.asdf/shims:$HOME/.cargo/bin:$HOME/.dojo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; [ -f "$HOME/.asdf/asdf.sh" ] && . "$HOME/.asdf/asdf.sh"; [ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"; '

if ([string]::IsNullOrWhiteSpace($env:SCARB_WSL_BIN)) {
    $scarbCommand = "scarb"
} else {
    $scarbCommand = Quote-Bash $env:SCARB_WSL_BIN
}

$command = $setupPath + "cd " + (Quote-Bash $wslCwd) + " && " + $scarbCommand + " " + ($quotedArgs -join " ")

& wsl bash -lc $command
exit $LASTEXITCODE
