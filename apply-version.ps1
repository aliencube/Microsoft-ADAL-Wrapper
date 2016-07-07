# This script update version.
Param(
	[string] [Parameter(Mandatory=$true)] $Version
)

$exitCode = 0
$projects = Get-ChildItem .\src | ?{$_.PsIsContainer}
foreach($project in $projects)
{
	$projectPath = $project.FullName
	$projectName = $project.Name

	Write-Host "Updating version of $projectName to $Version ..." -ForegroundColor Green

	$projectJson = Get-Content -Path $projectPath\project.json | ConvertFrom-Json
	$projectJson.version = $Version
	$projectJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $projectPath\project.json -Encoding utf8

	if ($LASTEXITCODE -ne 0)
	{
		Write-Host "Updating version of $projectName to $Version failure" -ForegroundColor Red
	}
	else
	{
		Write-Host "Updating version of $projectName to $Version success" -ForegroundColor Green
	}

	$exitCode += $LASTEXITCODE
}

if($exitCode -ne 0) {
	$host.SetShouldExit($exitCode)
}
