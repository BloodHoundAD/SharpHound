function Out-CompressedDll
{
<#
.SYNOPSIS

Creates the powershell in-memory version of SharpHound. 
Based entirely off Out-CompressedDll by Matthew Graeber (@mattifestation)
Original script at https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-CompressedDll.ps1
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [String]
        $FilePath,

        [Parameter(Mandatory = $True)]
        [String]
        $TemplatePath
    )

    $Path = Resolve-Path $FilePath

    if (! [IO.File]::Exists($Path))
    {
        Throw "$Path does not exist."
    }

    $FileBytes = [System.IO.File]::ReadAllBytes($Path)

    if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')
    {
        Throw "$Path is not a valid executable."
    }

    $Length = $FileBytes.Length
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($FileBytes, 0, $FileBytes.Length)
    $DeflateStream.Dispose()
    $CompressedFileBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedFile = [Convert]::ToBase64String($CompressedFileBytes)

    Write-Verbose "Compression ratio: $(($EncodedCompressedFile.Length/$FileBytes.Length).ToString('#%'))"

    $Output = @"
	`$EncodedCompressedFile = '$EncodedCompressedFile`'
	`$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`$EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
	`$UncompressedFileBytes = New-Object Byte[]($Length)
	`$DeflatedStream.Read(`$UncompressedFileBytes, 0, $Length) | Out-Null
	`$Assembly = [Reflection.Assembly]::Load(`$UncompressedFileBytes)
	`$BindingFlags = [Reflection.BindingFlags] "Public,Static"
	`$a = @()
	`$Assembly.GetType("Costura.AssemblyLoader", `$false).GetMethod("Attach", `$BindingFlags).Invoke(`$Null, @())
	`$Assembly.GetType("Sharphound.Program").GetMethod("InvokeSharpHound").Invoke(`$Null, @(,`$passed))
"@

	Get-Content $TemplatePath | %{$_ -replace "#ENCODEDCONTENTHERE", $Output}
}
