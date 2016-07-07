# This script runs tests.
Param(
	[string] [Parameter(Mandatory=$false)] $Configuration = "Debug"
)

# Tests each project
$exitCode = 0
$projects = Get-ChildItem .\test | ?{$_.PsIsContainer}
foreach($project in $projects)
{
	$projectPath = $project.FullName
	$projectName = $project.Name

	# Display project name
	Write-Host "Testing $projectName  with $Configuration settings ..." -ForegroundColor Green

	dotnet test $projectPath --configuration $Configuration

	if ($LASTEXITCODE -ne 0)
	{
		Write-Host "Test $projectName failure" -ForegroundColor Red
	}
	else
	{
		Write-Host "Test $projectName success" -ForegroundColor Green
	}

	$exitCode += $LASTEXITCODE
}

if($exitCode -ne 0) {
	$host.SetShouldExit($exitCode)
}
