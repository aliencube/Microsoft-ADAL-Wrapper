# This script runs solution build.
Param(
	[string] [Parameter(Mandatory=$false)] $Configuration = "Debug"
)

# Restores NuGet packages
Write-Host "Restoring NuGet packages ..." -ForegroundColor Green

dotnet restore

Write-Host "NuGet packages restored" -ForegroundColor Green

# Builds each project
$exitCode = 0
$projects = Get-ChildItem .\src, .\test | ?{$_.PsIsContainer}
foreach($project in $projects)
{
	$projectPath = $project.FullName
	$projectName = $project.Name

	Write-Host "Building $projectName with $Configuration settings ..." -ForegroundColor Green

	dotnet build $projectPath --configuration $Configuration

	if ($LASTEXITCODE -ne 0)
	{
		Write-Host "Building $projectName failure" -ForegroundColor Red
	}
	else
	{
		Write-Host "Building $projectName success" -ForegroundColor Green
	}

	$exitCode += $LASTEXITCODE
}

if($exitCode -ne 0) {
	$host.SetShouldExit($exitCode)
}
