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

    return $Path
}

function Quote-Bash {
    param([string]$Value)

    return "'" + $Value.Replace("'", "'\''") + "'"
}

$convertedArgs = $RemainingArgs | ForEach-Object { Convert-ToWslPath $_ }
$quotedArgs = $convertedArgs | ForEach-Object { Quote-Bash $_ }
$wslCwd = Convert-ToWslPath (Get-Location).Path
$setupPath = 'export PATH="$HOME/.local/bin:$HOME/.starkup/bin:$HOME/.asdf/shims:$HOME/.cargo/bin:$HOME/.dojo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; [ -f "$HOME/.asdf/asdf.sh" ] && . "$HOME/.asdf/asdf.sh"; [ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"; '
$corelibSetup = 'cd ' + (Quote-Bash $wslCwd) + ' && if [ ! -e corelib ] && [ -d "$HOME/cairo/corelib" ]; then ln -s "$HOME/cairo/corelib" corelib; fi && '

if ([string]::IsNullOrWhiteSpace($env:CAIRO_EXECUTE_WSL_BIN)) {
    $tool = "cairo-execute"
} else {
    $tool = Quote-Bash $env:CAIRO_EXECUTE_WSL_BIN
}

$command = $setupPath + $corelibSetup + $tool + " " + ($quotedArgs -join " ")

& wsl bash -lc $command
exit $LASTEXITCODE
