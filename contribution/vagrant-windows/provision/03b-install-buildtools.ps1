# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 03b-install-buildtools.ps1 -- Install the Windows driver build toolchain.
#
# This is a ONE-TIME provisioner (no run: "always" in the Vagrantfile).
# It installs:
#   - Visual Studio 2022 Build Tools with C++ workload + Windows 11 SDK
#     (provides MSBuild, cl.exe, link.exe, mc.exe, signtool, inf2cat)
#   - WiX Toolset v3 - for building the MSI installer
#
# NOTE: The Windows Driver Kit (WDK) requires an interactive user session
# (Windows Session 1 / RDP) to install. The WinRM communicator used by Vagrant
# runs in Session 0 (service context) and the wdksetup.exe bootstrapper exits
# 1001 in that environment. This script downloads wdksetup.exe to
# C:\wdksetup.exe and prints RDP instructions. You run it once via RDP.
#
# The CI (windows-2022 runner) has VS Enterprise + WDK pre-installed in the
# machine image, so it never needs to run wdksetup.exe.
#
# After WDK is manually installed once, every `vagrant provision` rebuilds
# driver + exe + MSI identically to the release CI (Build-WindowsArtifacts.ps1).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [03b] Installing Windows build toolchain (VS Build Tools, WiX)"

$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

function Invoke-Download {
    param([string]$Url, [string]$Dest)
    Write-Host "Downloading to $Dest ..."
    # curl.exe ships with Windows Server 2022. It handles stalls with --retry,
    # shows progress, and respects timeouts -- unlike WebClient.DownloadFile
    # which hangs forever on a frozen connection.
    & curl.exe --location --fail --silent --show-error `
        --retry 3 --retry-delay 5 --connect-timeout 60 `
        --output $Dest $Url
    if ($LASTEXITCODE -ne 0) {
        Write-Error "curl.exe failed (exit $LASTEXITCODE) downloading $Url"
        exit 1
    }
    $size = (Get-Item $Dest -ErrorAction SilentlyContinue).Length
    Write-Host "Downloaded: $Dest ($([math]::Round($size/1MB, 1)) MB)"
}

# ---- 1. Visual Studio 2022 Build Tools + Windows 11 SDK ----------------------
# We use Chocolatey (not the raw bootstrapper) because vs_buildtools.exe
# exits 5008 in WinRM/non-interactive sessions when it tries to self-update.
# Chocolatey handles the install context correctly.
#
# Components installed:
#   VCTools            -- C++ compiler, linker (cl.exe, link.exe)
#   VC.Tools.x86.x64  -- x64 toolset
#   Windows11SDK.22621 -- mc.exe, signtool.exe, inf2cat.exe, SDK headers
#   VC.ATL             -- ATL headers (needed by driver)
#   MSBuild            -- MSBuild.exe

$msbuildSearch = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio" `
    -Recurse -Filter "MSBuild.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($msbuildSearch) {
    Write-Host "VS Build Tools already installed at $($msbuildSearch.FullName) -- skipping."

    # Verify VC++ tools are present (VS2022VCTOOLSREQUIRED must be true for WDK)
    $clExe = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" `
        -Recurse -Filter "cl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $clExe) {
        Write-Host "VC++ compiler (cl.exe) not found. Adding VCTools workload to existing VS install..."
        $vsInstaller = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vs_installer.exe"
        if (Test-Path $vsInstaller) {
            $proc = Start-Process $vsInstaller -Wait -PassThru -ArgumentList @(
                "modify", "--installPath",
                "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
                "--add", "Microsoft.VisualStudio.Workload.VCTools",
                "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
                "--add", "Microsoft.VisualStudio.Component.VC.ATL",
                "--add", "Microsoft.Component.MSBuild",
                "--quiet", "--norestart"
            )
            Write-Host "VCTools workload modify exit: $($proc.ExitCode)"
        }
    } else {
        Write-Host "VC++ compiler found at $($clExe.FullName) -- OK."
    }
} else {
    Write-Host "Installing VS Build Tools 2022 with VC++ workload via Chocolatey..."
    # IMPORTANT: --package-parameters must be a single quoted string.
    # Multi-word strings split on spaces and are silently ignored by Chocolatey,
    # resulting in the VS shell-only install (no C++ compiler = no WDK support).
    choco install visualstudio2022buildtools --yes --no-progress `
        --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --add Microsoft.VisualStudio.Component.VC.ATL --add Microsoft.Component.MSBuild --passive --norestart"

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Chocolatey VS Build Tools install failed (exit $LASTEXITCODE)"
        exit 1
    }
    Write-Host "VS Build Tools 2022 + VC++ workload installed."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}


# ---- 1b. Register VS2022 VC++ SxS path (VS2022VCTOOLSREQUIRED) ---------------
# The WDK 22621 installer checks two distinct VS2022 registry keys:
#   VS2022INSTALL        <- HKLM\...\SxS\VS7\17.0   (IDE path)
#   VS2022VCTOOLSREQUIRED <- HKLM\...\SxS\VC7\17.0  (C++ compiler path)
#
# VS2022 BUILD TOOLS installed via Chocolatey registers SxS\VS7\17.0 correctly
# but does NOT register SxS\VC7\17.0. The full VS2022 IDE does both.
#
# The WDK feature OptionId.WindowsDriverKit requires:
#   (VS2022INSTALL) AND (VS2022VCTOOLSREQUIRED) = true
# Without SxS\VC7\17.0, VS2022VCTOOLSREQUIRED = false -> feature disabled.
#
# Fix: manually add the VC7 SxS entry pointing to the BuildTools VC\ directory.

$vcPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\"
if (Test-Path $vcPath) {
    try {
        foreach ($key in @(
            "HKLM:\SOFTWARE\Microsoft\VisualStudio\SxS\VC7",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VC7"
        )) {
            if (-not (Test-Path $key)) { New-Item $key -Force | Out-Null }
            Set-ItemProperty $key -Name "17.0" -Value $vcPath -Type String
        }
        Write-Host "VS2022 SxS\VC7\17.0 registered -> VS2022VCTOOLSREQUIRED will be true."
    } catch {
        Write-Warning "SxS\VC7 registration failed (non-fatal): $_"
    }
} else {
    Write-Warning "VC++ path not found at $vcPath -- WDK may fail VS2022VCTOOLSREQUIRED check."
}

# NOTE: We use a simple Set-ItemProperty here (NOT reg.exe and NOT inside the
# same run as VS Build Tools install). reg.exe hangs when the Windows Installer
# service holds a registry hive lock after VS Build Tools installation.
# We only need these keys if VS2022INSTALL is NOT detected by the WDK installer.
# For WDK 22000, VS2022INSTALL alone satisfies the OptionId.WindowsDriverKit
# condition, so this is a belt-and-suspenders safety write done AFTER the VS
# installer service has had time to settle (we are called fresh after a reboot).

$sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (Test-Path $sdkRoot) {
    $sdkVersion = Get-ChildItem "$sdkRoot\Include" -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
    if (-not $sdkVersion) { $sdkVersion = "10.0.22621.0" }
    Write-Host "Detected SDK version: $sdkVersion"

    try {
        $regBase = "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
        $regWow  = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"
        foreach ($rp in @($regBase, $regWow)) {
            if (-not (Test-Path $rp)) { New-Item $rp -Force | Out-Null }
            Set-ItemProperty $rp -Name "KitsRoot10" -Value "$sdkRoot\" -Type String
            Set-ItemProperty $rp -Name $sdkVersion  -Value "$sdkRoot\" -Type String
        }
        Write-Host "SDK registry keys written (KitsRoot10 = $sdkRoot\)."
    } catch {
        Write-Warning "SDK registry write failed (non-fatal): $_"
        Write-Warning "The WDK installer will rely on VS2022INSTALL detection instead."
    }
}

# ---- 3. Windows Driver Kit (WDK) 10.0.22000 ----------------------------------
#
# WDK 19041 requires VS2019INSTALL; WDK 22621 exits 1001 (OS version check on
# Server 2022 build 20348 which is < 22621). WDK 22000 checks VS2022INSTALL
# and may have a looser OS floor.
#
# DOWNLOAD STRATEGY:
#   The Windows VM's network can be unreliable for large downloads (~400 MB).
#   If wdksetup.exe is pre-downloaded to the shared repo folder on the Linux host:
#     /path/to/KubeArmor/contribution/vagrant-windows/wdksetup.exe
#   it is available inside the VM at:
#     C:\KubeArmor\contribution\vagrant-windows\wdksetup.exe
#   Download on the Linux host with:
#     wget "https://go.microsoft.com/fwlink/?linkid=2166289" \
#          -O contribution/vagrant-windows/wdksetup.exe

$wdkMarker   = "${env:ProgramFiles(x86)}\Windows Kits\10\Include"
$wdkInstalled = (Get-ChildItem $wdkMarker -Filter "wdm.h" -Recurse -ErrorAction SilentlyContinue |
    Measure-Object).Count -gt 0

if ($wdkInstalled) {
    Write-Host "WDK kernel headers already present (wdm.h found) -- skipping."
} else {
    $wdkDest = "C:\wdksetup.exe"

    # Priority 1: pre-downloaded via shared folder (avoids VM network issues)
    $sharedWdk = "C:\KubeArmor\contribution\vagrant-windows\wdksetup.exe"
    if (Test-Path $sharedWdk) {
        Write-Host "Using pre-downloaded WDK installer from shared folder: $sharedWdk"
        Copy-Item $sharedWdk $wdkDest -Force
    } elseif (-not (Test-Path $wdkDest)) {
        # Priority 2: download from Microsoft CDN
        Write-Host "Downloading WDK 10.0.22000 from Microsoft CDN (~400 MB)..."
        Write-Host "(Pre-download on Linux host to avoid VM network issues:"
        Write-Host "  wget 'https://go.microsoft.com/fwlink/?linkid=2166289' -O contribution/vagrant-windows/wdksetup.exe)"
        Invoke-Download "https://go.microsoft.com/fwlink/?linkid=2166289" $wdkDest
    } else {
        Write-Host "WDK installer already at $wdkDest"
    }

    # --------------------------------------------------------------------------
    # STRATEGY: Bypass the WDK bootstrapper entirely.
    #
    # The wdksetup.exe WiX Burn bootstrapper uses a custom BA DLL that queries
    # ISetupConfiguration2 to detect VS2022 VCTools. On Server 2022, this COM
    # query NEVER succeeds (regardless of execution context: WinRM, SYSTEM,
    # interactive), so VS2022VCTOOLSREQUIRED is never set and the
    # OptionId.WindowsDriverKit feature is gated off.
    #
    # However, the individual MSI packages inside the bundle have NO install
    # conditions. We use "wdksetup.exe /layout" to download ALL packages to a
    # local folder (layout mode skips the BA DLL's VS check), then install the
    # required WDK MSIs directly with msiexec.
    # --------------------------------------------------------------------------

    $wdkLog    = "C:\wdk-install.log"
    $layoutDir = "C:\wdk-layout"

    # Step 1: Download WDK packages via /layout (no VS check)
    if (-not (Test-Path "$layoutDir\Installers")) {
        Write-Host "Step 1: Downloading WDK packages via /layout..."
        Write-Host "  (This downloads ~800 MB of MSI/CAB files. May take 10-30 min.)"

        $taskName  = "KubeArmor-WDK-Layout"
        $layoutArgs = "/layout `"$layoutDir`" /quiet /log `"$wdkLog`""
        $action    = New-ScheduledTaskAction -Execute $wdkDest -Argument $layoutArgs -WorkingDirectory "C:\"
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask   -TaskName $taskName -Action $action -Settings $settings -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        $deadline = (Get-Date).AddMinutes(120)
        $lastSize = 0
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 20
            $state = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
            if ($state -ne "Running") { break }
            # Heartbeat: show download progress by folder size
            $curSize = 0
            if (Test-Path $layoutDir) {
                $curSize = [math]::Round((Get-ChildItem $layoutDir -Recurse -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum / 1MB)
            }
            Write-Host "  [layout] downloading... ${curSize} MB so far"
            $lastSize = $curSize
        }

        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $exitCode = if ($taskInfo) { $taskInfo.LastTaskResult } else { -1 }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        if ($exitCode -notin @(0, 3010)) {
            Write-Host "---- WDK layout log (last 40 lines) ----"
            Get-Content $wdkLog -ErrorAction SilentlyContinue | Select-Object -Last 40
            Write-Host "----------------------------------------"
            Write-Error "WDK layout download failed (exit $exitCode / 0x$($exitCode.ToString('X')))"
            exit 1
        }
        Write-Host "WDK layout download complete."
    } else {
        Write-Host "Step 1: WDK layout already exists at $layoutDir -- skipping download."
    }

    # Step 2: Install WDK MSIs directly with msiexec (bypasses bootstrapper)
    Write-Host "Step 2: Installing WDK MSI packages directly (bypassing bootstrapper)..."

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\"
    $msiDir   = "$layoutDir\Installers"

    # Core WDK packages in dependency order
    $wdkMsis = @(
        "Kits Configuration Installer-x86_en-us.msi",
        "Windows Driver Kit Headers and Libs-x86_en-us.msi",
        "Windows Driver Framework Headers and Libs-x86_en-us.msi",
        "Windows Driver Kit Binaries-x86_en-us.msi",
        "Windows Driver Kit-x86_en-us.msi",
        "Windows Driver Kit SxS Content-x86_en-us.msi",
        "Windows Content Versioned-x86_en-us.msi",
        "Windows Debugging WDK Integration Versioned-x86_en-us.msi",
        "Windows Driver Kit Root Dev17 Content-x86_en-us.msi",
        "Windows Driver Kit Visual Studio Dev17 Content-x86_en-us.msi"
    )

    $allOk = $true
    foreach ($msi in $wdkMsis) {
        $msiPath = Join-Path $msiDir $msi
        if (-not (Test-Path $msiPath)) {
            Write-Warning "MSI not found: $msiPath -- skipping"
            continue
        }
        Write-Host "  Installing: $msi"
        $msiLog = "C:\wdk-msi-$($msi -replace '[^a-zA-Z0-9]','_').log"
        $p = Start-Process -FilePath "msiexec.exe" -Wait -PassThru -ArgumentList @(
            "/i", "`"$msiPath`"",
            "/quiet", "/norestart",
            "KITSROOT=`"$kitsRoot`"",
            "KITSOPTION=OptionId.WindowsDriverKitComplete",
            "ARPSYSTEMCOMPONENT=1",
            "MSIFASTINSTALL=7",
            "/log", "`"$msiLog`""
        )
        if ($p.ExitCode -notin @(0, 3010, 1603)) {
            Write-Warning "  $msi failed (exit $($p.ExitCode)). See $msiLog"
            $allOk = $false
        } elseif ($p.ExitCode -eq 1603) {
            # 1603 = fatal error; check if already installed
            Write-Warning "  $msi exit 1603 (may already be installed)"
        } else {
            Write-Host "  $msi OK (exit $($p.ExitCode))"
        }
    }

    if (-not $allOk) {
        Write-Warning "Some WDK MSIs had errors. Checking if headers were installed anyway..."
    }

    $wdmOk = (Get-ChildItem $wdkMarker -Filter "wdm.h" -Recurse -ErrorAction SilentlyContinue |
        Measure-Object).Count -gt 0
    if (-not $wdmOk) {
        Write-Error "WDK installation failed -- wdm.h not found after MSI installation."
        exit 1
    } else {
        Write-Host "WDK headers verified (wdm.h present)."
    }

    # Step 3: Install WDK VSIX (MSBuild platform toolset integration)
    $vsixPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Vsix\VS2022\10.0.22621.0\WDK.vsix"
    $vsRoot   = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools"
    $toolsetCheck = "$vsRoot\MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0"

    if (Test-Path $toolsetCheck) {
        Write-Host "Step 3: WindowsKernelModeDriver10.0 toolset already installed -- skipping VSIX."
    } elseif (Test-Path $vsixPath) {
        Write-Host "Step 3: Installing WDK VSIX (MSBuild driver toolset)..."
        $tempDir = "C:\wdk-vsix-extract"
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($vsixPath, $tempDir)

        $v170Src = "$tempDir\`$MSBuild\Microsoft\VC\v170"
        $v170Dst = "$vsRoot\MSBuild\Microsoft\VC\v170"
        if (Test-Path $v170Src) {
            Copy-Item -Path "$v170Src\*" -Destination $v170Dst -Recurse -Force
            Write-Host "WindowsKernelModeDriver10.0 toolset installed."
        } else {
            Write-Warning "VSIX did not contain expected v170 directory."
        }
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Warning "WDK VSIX not found at $vsixPath -- driver build may fail."
    }
}

# ---- 4. WiX Toolset v3 (MSI packaging) ---------------------------------------

$wixTargets = Get-ChildItem "${env:ProgramFiles(x86)}\MSBuild" -Recurse `
    -Filter "wix.targets" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName

if ($wixTargets) {
    Write-Host "WiX v3 already installed at: $wixTargets -- skipping."
} else {
    Write-Host "Installing WiX Toolset v3..."
    choco install wixtoolset --yes --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Error "WiX install failed (exit $LASTEXITCODE)"
        exit 1
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + $env:Path
}

# ---- 5. Verify toolchain ------------------------------------------------------

Write-Host ""
Write-Host "--- Toolchain verification ---"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $msbuild = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.Component.MSBuild `
        -find "MSBuild\**\Bin\MSBuild.exe" 2>$null | Select-Object -First 1
    if ($msbuild) {
        $ver = (& $msbuild /version /nologo 2>&1 | Select-Object -First 1).Trim()
        Write-Host "MSBuild : $msbuild  ($ver)"
    } else {
        Write-Warning "MSBuild not found via vswhere"
    }
}

$wdkBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
$mcExe = Get-ChildItem $wdkBin -Recurse -Filter "mc.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -Last 1 -ExpandProperty FullName
Write-Host "mc.exe  : $(if ($mcExe) { $mcExe } else { 'NOT FOUND' })"

$signtool = Get-ChildItem $wdkBin -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -Last 1 -ExpandProperty FullName
Write-Host "signtool: $(if ($signtool) { $signtool } else { 'NOT FOUND' })"

$wdmHeader = Get-ChildItem $wdkMarker -Filter "wdm.h" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
Write-Host "wdm.h   : $(if ($wdmHeader) { $wdmHeader } else { 'NOT FOUND -- WDK not yet installed, see instructions above' })"

$wixCheck = Get-ChildItem "${env:ProgramFiles(x86)}\MSBuild" -Recurse `
    -Filter "wix.targets" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
Write-Host "WiX     : $(if ($wixCheck) { $wixCheck } else { 'NOT FOUND' })"

if (-not $wdmHeader) {
    Write-Warning "WDK not installed. Run the driver build (step 07) AFTER installing WDK via RDP."
}

Write-Host ""
Write-Host "==> [03b] Build toolchain setup complete"
