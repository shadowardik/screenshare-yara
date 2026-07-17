$rulesDir = Read-Host "Enter the path to the folder with YARA rules (for example, C:\yara\rules)"
$pathsFile = Read-Host "Enter the path to the file with the list of paths to scan (e.g. C:\scan\targets.txt)"

$rulesDir = $rulesDir.Trim('"').Trim("'")
$pathsFile = $pathsFile.Trim('"').Trim("'")

if (-not (Test-Path -Path $rulesDir -PathType Container)) {
    Write-Error "Error: YARA rules folder not found at path: $rulesDir"
    Exit
}

if (-not (Test-Path -Path $pathsFile -PathType Leaf)) {
    Write-Error "Error: File containing the list of paths not found: $pathsFile"
    Exit
}

$yaraRules = Get-ChildItem -Path $rulesDir -Filter "*.yar*" -File | Select-Object -ExpandProperty FullName

if ($yaraRules.Count -eq 0) {
    Write-Warning "No files with the .yar or .yara extension were found in the '$rulesDir' folder."
    Exit
}

Write-Host "`n[+] YARA rules found: $($yaraRules.Count)" -ForegroundColor Green
Write-Host "[+] Reading paths to scan from: $pathsFile`n" -ForegroundColor Green

$targets = Get-Content -Path $pathsFile | Where-Object { $_.Trim() -ne "" }
$scanResults = [System.Collections.Generic.List[string]]::new()

foreach ($target in $targets) {
    $targetPath = $target.Trim().Trim('"').Trim("'")

    if (-not (Test-Path -Path $targetPath)) {
        Write-Host "[-] File not found, skip: $targetPath" -ForegroundColor Yellow
        continue
    }

    Write-Host "--- Scanning: $targetPath ---" -ForegroundColor Cyan

    foreach ($rule in $yaraRules) {
        $output = & "./yara64.exe" --no-warnings "$rule" "$targetPath" 2>$null
        if ($output) {
            foreach ($line in $output) {
                if ($line.Trim() -ne "") {
                    Write-Host "[!] Match: $line" -ForegroundColor Red
                    $scanResults.Add($line)
                }
            }
        }
    }
}

Write-Host "`n[+] Scanning complete." -ForegroundColor Green

Write-Host "`n================ DETECTED MATCHES ================" -ForegroundColor Red
if ($scanResults.Count -gt 0) {
    foreach ($match in $scanResults) {
        Write-Host $match -ForegroundColor Red
    }
} else {
    Write-Host "No matches found." -ForegroundColor Green
}
Write-Host "==================================================" -ForegroundColor Red