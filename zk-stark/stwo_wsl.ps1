param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("run_and_prove", "verify")]
    [string]$Tool,

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

$pathOptions = @(
    "--program",
    "--proof_path",
    "--params_json",
    "--program_arguments_file"
)

$convertedArgs = [System.Collections.Generic.List[string]]::new()
$convertNext = $false

foreach ($arg in $RemainingArgs) {
    if ($convertNext) {
        $convertedArgs.Add((Convert-ToWslPath $arg))
        $convertNext = $false
        continue
    }

    $convertedArgs.Add($arg)
    if ($pathOptions -contains $arg) {
        $convertNext = $true
    }
}

$wslProverDir = $env:STWO_WSL_PROVER_DIR
if ([string]::IsNullOrWhiteSpace($wslProverDir)) {
    $wslProverDir = "~/stwo-cairo/stwo_cairo_prover"
}

$binary = "$wslProverDir/target/release/$Tool"
$quotedArgs = $convertedArgs | ForEach-Object { Quote-Bash $_ }
if ($binary.StartsWith("~/")) {
    $binaryCommand = '"$HOME"/' + (Quote-Bash $binary.Substring(2))
} else {
    $binaryCommand = Quote-Bash $binary
}
$command = $binaryCommand + " " + ($quotedArgs -join " ")

& wsl bash -lc $command
exit $LASTEXITCODE
