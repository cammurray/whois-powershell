#Requires -Version 5.1

<#
	.SYNOPSIS
		Domain and IP Whois Module for PowerShell

	.DESCRIPTION
       Domain and IP Whois Module for PowerShell

    .NOTES
    
        Cam Murray
        cam@camm.id.au
        
        ############################################################################

        This program is free software: you can redistribute it and/or modify it under the terms of
        the GNU General Public License as published by the Free Software Foundation, either version
        3 of the License.  This program is distributed in the hope that it will be useful, but
        WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
        A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

        You should have received a copy of the GNU General Public License along with this program.
        If not, see <https://www.gnu.org/licenses/gpl-3.0.en.html>.

        ############################################################################    

	.LINK
        about_functions_advanced

#>

Function Get-RawWhoisData
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Server="whois.arin.net",
        [Int]
        $Port = 43,
        $Target
    )

    try
	{
		$Socket = New-Object System.Net.Sockets.TcpClient( $Server, $port )
	}
	catch
	{
		Write-Host -ForegroundColor Red "failed"
		Throw "Cannot connect to $($Server) on port $($Port)"
    }
    
    $stream = $socket.GetStream( )
	$writer = New-Object System.IO.StreamWriter( $stream )
	$buffer = New-Object System.Byte[] 1024
    $encoding = New-Object System.Text.AsciiEncoding
    
    # Send the request

    $writer.WriteLine($Target)
    $writer.Flush()

    Start-Sleep 1

    # Receive the response
    while( $stream.DataAvailable )
    {
        $read = $stream.Read( $buffer, 0, 1024 )
        $encoding.GetString( $buffer, 0, $read )
    }

    # Close off
	if( $writer ) {	$writer.Close( )	}
	if( $stream ) {	$stream.Close( )	}
}

Function Get-Whois
{
    [CmdletBinding()]
    param (
        [Parameter(Position=0,Mandatory=$True)]
        $Target,
        [String]
        $Server="whois.iana.org",
        [Int]
        $Port = 43,
        [Switch]
        $Referred
    )

    # Get the raw unparsed whois results and split it by new lines
    $RawData = (Get-RawWhoisData -Server $Server -Port $Port -Target $Target).Split([Environment]::NewLine)

    # For returning the results
    $Result = New-Object -TypeName PSObject
    $Object = New-Object -TypeName PSObject

    $ObjectName = $Null

    ForEach($Line in $RawData)
    {

        # Some whois servers end with a comment section like this >>> Last update of whois database: xxxxx-xxxx-xxxx <<<
        If($Line -match "^>>>.*<<<$")
        {
            # It's the end, so stop parsing
            break
        }

        # Determine if is a comment line
        if($Line -notmatch "^%")
        {
            # Determine if this is a field or a start of a segment

            if($Line -match "(^.*?):(.*)$")
            {

                # Get the field for the first match, 
                $Field = $Matches[1].Replace(" ","").Trim()
                $FieldValue = $Matches[2].Trim()

                # Is this the first, then its the start of a new object
                If($Null -eq $ObjectName)
                {
                    $ObjectName = $Field
                }

                # Determine if the FieldValue appears to be a DateTime
                If($FieldValue -match "^\d\d\d\d-\d\d-\d\d")
                {
                    $OldValue = $FieldValue
                    try {
                        $FieldValue = [DateTime]::Parse($OldValue)
                    }
                    catch {
                        # Fail by setting it back
                        $FieldValue = $OldValue
                    }
                }

                # This is a field

                # Determine if already exists (if so concat the results), if not it's a new property
                if($Field -ne "")
                {
                    If($null -ne $Object.$Field)
                    {
                        $Object.$Field += $FieldValue
                    }
                    else 
                    {
                        $Object | Add-Member -NotePropertyName $Field -NotePropertyValue $FieldValue
                    }
                }
                
            }
            else 
            {
                # This is the end of a object

                # Determine if there are any fields in this object and if so, add it to the Result object and then clear the object.
                If(@(($Object | Get-member) | Where-Object {$_.MemberType -eq "NoteProperty"}).Count -gt 0)
                {

                    # Is this a single property object, avoid duplication of the name
                    If(@(($Object | Get-member) | Where-Object {$_.MemberType -eq "NoteProperty"}).Count -eq 1)
                    {
                        $Object = $Object.$ObjectName
                    }

                    # Add to the returning object

                    # First determine if there is already an entry under this name
                    If($Null -ne $Result.$ObjectName)
                    {
                        # Determine if already an array
                        If($Result.$ObjectName -is [Array])
                        {
                            # Add to the existing array
                            $Result.$ObjectName += $Object
                        }
                        else 
                        {
                            # Recast as an array, and re-add object, and new object
                            $OldObject = $Result.$ObjectName

                            $Result.$ObjectName = @()
                            $Result.$ObjectName += $OldObject
                            $Result.$ObjectName += $Object
                        }
                    }
                    else 
                    {
                        # This is a new object name
                        $Result | Add-Member -NotePropertyName $ObjectName -NotePropertyValue $Object
                    }

                    # Clear the object for the next one
                    $ObjectName = $Null
                    $Object = New-Object -TypeName psobject
                }
            }
        }
    }

    # Determine if there is a referer
    If($null -ne $Result.refer)
    {
        # Ensure that we're not already referred (to stop a loop)
        If(!$Referred)
        {
            $Result = Get-Whois -Server $Result.refer -Target $Target -Referred
        }
        else 
        {
            # It appears we are referred twice, this could cause a loop.
            Throw("Whois has been referred twice, meaning there's a possible loop. Not continuing.")    
        }
    }

    Return $Result

}