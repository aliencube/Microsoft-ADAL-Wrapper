# This script builds NuGet package.

# Builds each project
$exitCode = 0
$projects = Get-ChildItem .\src | ?{$_.PsIsContainer}
foreach($project in $projects)
{
	$projectPath = $project.FullName
	$projectName = $project.Name

	Write-Host "Building NuGet package for $projectName ..." -ForegroundColor Green

	dotnet pack $projectPath --configuration Release

	if ($LASTEXITCODE -ne 0)
	{
		Write-Host "Building NuGet package for $projectName failure" -ForegroundColor Red
	}
	else
	{
		Write-Host "Building NuGet package for $projectName success" -ForegroundColor Green
	}

	$exitCode += $LASTEXITCODE
}

if($exitCode -ne 0) {
	$host.SetShouldExit($exitCode)
}
