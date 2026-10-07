Set-Location $PSScriptRoot
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$zkStark = (Resolve-Path (Join-Path $PSScriptRoot "..\..\zk-stark")).Path
$zkRisc0 = (Resolve-Path (Join-Path $PSScriptRoot "..\..\zk-risc0")).Path
$env:AUTHLIB_JOSE_MAX_CIPHERTEXT_SIZE = "16777216"
$env:STWO_RUN_AND_PROVE = Join-Path $zkStark "run_and_prove_wsl.cmd"
$env:STWO_VERIFY = Join-Path $zkStark "verify_wsl.cmd"
$env:STWO_SCARB = Join-Path $zkStark "scarb_wsl.cmd"
$env:STWO_CAIRO_EXECUTE = Join-Path $zkStark "cairo_execute_wsl.cmd"
$env:STWO_CHANNEL_HASH = "blake2s"
$env:STWO_ALLOW_NATIVE_WINDOWS = "0"
$env:RISC0_CREDENTIAL_CLI = Join-Path $zkRisc0 "risc0_wsl.cmd"
if ([string]::IsNullOrWhiteSpace($env:DIDSSO_PROOF_BACKEND)) {
    $env:DIDSSO_PROOF_BACKEND = "risc0"
}
$env:DIDSSO_PROOF_BACKEND = $env:DIDSSO_PROOF_BACKEND.ToLowerInvariant()
if ($env:DIDSSO_PROOF_BACKEND -notin @("risc0", "stwo")) {
    throw "DIDSSO_PROOF_BACKEND must be either 'risc0' or 'stwo'"
}
Remove-Item Env:RISC0_DEV_MODE -ErrorAction SilentlyContinue
Remove-Item Env:STWO_PARAMS_JSON -ErrorAction SilentlyContinue
Write-Host "Registration proof: $($env:DIDSSO_PROOF_BACKEND.ToUpperInvariant())"
Write-Host "Authlib JWE ciphertext limit: $env:AUTHLIB_JOSE_MAX_CIPHERTEXT_SIZE characters"
$pythonCandidate = if ([string]::IsNullOrWhiteSpace($env:DIDSSO_PYTHON)) {
    Join-Path $workspaceRoot ".venv-didcomm\Scripts\python.exe"
}
else {
    $env:DIDSSO_PYTHON
}
if (-not (Test-Path -LiteralPath $pythonCandidate -PathType Leaf)) {
    throw "DIDComm runtime not found at '$pythonCandidate'. Run .\setup-runtime.ps1 from the DIDSSO root or set DIDSSO_PYTHON."
}
$pythonExecutable = (Resolve-Path -LiteralPath $pythonCandidate).Path
$serverProcess = Start-Process `
    -FilePath $pythonExecutable `
    -ArgumentList @("-u", ".\server.py") `
    -NoNewWindow `
    -PassThru
$serverExitCode = 0
$cancelRequested = $false
$cancelMonitorAvailable = $false

try {
    if ($null -eq ("DidSsoRawConsoleCancelMonitorV2" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class DidSsoRawConsoleCancelMonitorV2
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint EnableProcessedInput = 0x0001;
    private const ushort KeyEvent = 0x0001;
    private const ushort VirtualKeyC = 0x43;
    private const uint RightCtrlPressed = 0x0004;
    private const uint LeftCtrlPressed = 0x0008;
    private static readonly IntPtr InvalidHandle = new IntPtr(-1);
    private static readonly ManualResetEventSlim Cancellation = new ManualResetEventSlim(false);
    private static IntPtr consoleInput = InvalidHandle;
    private static uint originalConsoleMode;
    private static bool rawConsoleInput;
    private static bool started;

    public static bool RawConsoleInputEnabled
    {
        get { return rawConsoleInput; }
    }

    [StructLayout(LayoutKind.Explicit, Size = 20, CharSet = CharSet.Unicode)]
    private struct InputRecord
    {
        [FieldOffset(0)] public ushort EventType;
        [FieldOffset(4)] public int KeyDown;
        [FieldOffset(8)] public ushort RepeatCount;
        [FieldOffset(10)] public ushort VirtualKeyCode;
        [FieldOffset(12)] public ushort VirtualScanCode;
        [FieldOffset(14)] public char UnicodeChar;
        [FieldOffset(16)] public uint ControlKeyState;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr consoleHandle, out uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr consoleHandle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNumberOfConsoleInputEvents(IntPtr consoleInput, out uint count);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ReadConsoleInput(
        IntPtr consoleInput,
        out InputRecord inputRecord,
        uint length,
        out uint recordsRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static void Start()
    {
        Cancellation.Reset();
        if (!started)
        {
            Console.CancelKeyPress += HandleCancelKeyPress;
            StartRawConsoleInput();
            started = true;
        }
    }

    public static bool Wait(int milliseconds)
    {
        Stopwatch timer = Stopwatch.StartNew();
        do
        {
            if (Cancellation.IsSet || ReadBufferedCtrlC())
            {
                return true;
            }
            int remaining = Math.Max(0, milliseconds - (int)timer.ElapsedMilliseconds);
            if (remaining == 0)
            {
                return false;
            }
            Cancellation.Wait(Math.Min(remaining, 20));
        }
        while (true);
    }

    public static void Stop()
    {
        if (started)
        {
            Console.CancelKeyPress -= HandleCancelKeyPress;
            StopRawConsoleInput();
            started = false;
        }
        Cancellation.Reset();
    }

    private static void HandleCancelKeyPress(object sender, ConsoleCancelEventArgs args)
    {
        args.Cancel = true;
        Cancellation.Set();
    }

    private static void StartRawConsoleInput()
    {
        consoleInput = CreateFile(
            "CONIN$",
            GenericRead | GenericWrite,
            ShareRead | ShareWrite,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (consoleInput == InvalidHandle || consoleInput == IntPtr.Zero)
        {
            return;
        }
        uint mode;
        if (GetConsoleMode(consoleInput, out mode))
        {
            originalConsoleMode = mode;
            rawConsoleInput = SetConsoleMode(consoleInput, mode & ~EnableProcessedInput);
        }
    }

    private static bool ReadBufferedCtrlC()
    {
        if (!rawConsoleInput)
        {
            return false;
        }
        uint count;
        while (GetNumberOfConsoleInputEvents(consoleInput, out count) && count > 0)
        {
            InputRecord input;
            uint recordsRead;
            if (!ReadConsoleInput(consoleInput, out input, 1, out recordsRead) || recordsRead == 0)
            {
                return false;
            }
            uint controlKeys = input.ControlKeyState;
            if (input.EventType == KeyEvent
                && input.KeyDown != 0
                && (input.UnicodeChar == (char)3
                    || (input.VirtualKeyCode == VirtualKeyC
                        && (controlKeys & (LeftCtrlPressed | RightCtrlPressed)) != 0)))
            {
                return true;
            }
        }
        return false;
    }

    private static void StopRawConsoleInput()
    {
        if (consoleInput != InvalidHandle && consoleInput != IntPtr.Zero)
        {
            if (rawConsoleInput)
            {
                SetConsoleMode(consoleInput, originalConsoleMode);
            }
            CloseHandle(consoleInput);
        }
        consoleInput = InvalidHandle;
        rawConsoleInput = false;
    }
}
"@
    }
    [DidSsoRawConsoleCancelMonitorV2]::Start()
    $cancelMonitorAvailable = $true
    if ([DidSsoRawConsoleCancelMonitorV2]::RawConsoleInputEnabled) {
        Write-Host "Ctrl+C shutdown monitor is ready"
    }
    else {
        Write-Warning "Raw console input is unavailable; Ctrl+C uses the Windows signal fallback"
    }
}
catch {
    Write-Warning "Could not install Ctrl+C monitor: $($_.Exception.Message)"
}

try {
    while (-not $serverProcess.HasExited) {
        if ($cancelMonitorAvailable -and [DidSsoRawConsoleCancelMonitorV2]::Wait(100)) {
            $cancelRequested = $true
            Write-Host "Stopping IdP DIDComm backend..."
            break
        }
        $null = $serverProcess.WaitForExit(100)
    }
    if ($serverProcess.HasExited) {
        $serverExitCode = $serverProcess.ExitCode
    }
}
finally {
    if ($cancelMonitorAvailable) {
        [DidSsoRawConsoleCancelMonitorV2]::Stop()
    }
    if (-not $serverProcess.HasExited) {
        if (-not $cancelRequested) {
            Write-Host "Stopping IdP DIDComm process tree..."
        }
        & "$env:SystemRoot\System32\taskkill.exe" /PID $serverProcess.Id /T /F | Out-Null
        $serverProcess.WaitForExit()
    }
    $serverProcess.Dispose()
}

if ($serverExitCode -ne 0) {
    exit $serverExitCode
}
