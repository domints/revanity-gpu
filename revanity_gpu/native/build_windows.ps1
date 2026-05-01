param(
    [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $root "build"

if (!(Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

cmake -S $root -B $buildDir -DCMAKE_BUILD_TYPE=$BuildType
cmake --build $buildDir --config $BuildType

$dllPath = Join-Path $buildDir "$BuildType\revanity_cuda.dll"
if (!(Test-Path $dllPath)) {
    $dllPath = Join-Path $buildDir "revanity_cuda.dll"
}

if (Test-Path $dllPath) {
    Copy-Item $dllPath (Join-Path $root "revanity_cuda.dll") -Force
    Write-Host "Built and copied:" (Join-Path $root "revanity_cuda.dll")
} else {
    Write-Warning "Build completed but revanity_cuda.dll not found in expected paths."
}
