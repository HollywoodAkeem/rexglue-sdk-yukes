$vsPath = & 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -latest -property installationPath
Import-Module "$vsPath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64' | Out-Null
Set-Location 'C:\Users\joelu\source\repos\rexglue-sdk'
cmake --build out/build/win-amd64 --config RelWithDebInfo --target install 2>&1
