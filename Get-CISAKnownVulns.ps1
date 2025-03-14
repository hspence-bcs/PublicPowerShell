<#
.SYNOPSIS
    Retrieves known exploited vulnerabilities from the CISA CSV file.

.DESCRIPTION
    This script fetches the known exploited vulnerabilities from the specified CISA CSV file URL.
    It allows filtering the data by application, vendor, and CVE ID.

.PARAMETER CISAcsv
    The URL of the CSV file containing known exploited vulnerabilities. Default is the CISA URL.

.PARAMETER Application
    The name of the application to filter the vulnerabilities by.

.PARAMETER Vendor
    The name of the vendor to filter the vulnerabilities by.

.PARAMETER CVE
    The CVE ID to filter the vulnerabilities by.

.EXAMPLE
    Get-CISAKnownVulnerabilities -Application "ExampleApp"
    Retrieves vulnerabilities for the specified application.

.EXAMPLE
    Get-CISAKnownVulnerabilities -Vendor "ExampleVendor"
    Retrieves vulnerabilities for the specified vendor.

.EXAMPLE
    Get-CISAKnownVulnerabilities -CVE "CVE-2021-12345"
    Retrieves vulnerabilities for the specified CVE ID.

.EXAMPLE
    Get-CISAKnownVulnerabilities -Application "ExampleApp" -Vendor "ExampleVendor" -CVE "CVE-2021-12345"
    Retrieves vulnerabilities for the specified application, vendor, and CVE ID.

.NOTES
    Author: Dave Spence
    Date: August 21, 2024
#>

function Get-CISAKnownVulnerabilities {
    param (
        [string]$CISAcsv = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv',
        [string]$Application,
        [string]$Vendor,
        [string]$CVE
    )

    try {
        # Fetch the CSV data from the specified URL
        $response = Invoke-WebRequest -Uri $CISAcsv -ErrorAction Stop

        # Convert the CSV data to PowerShell objects
        $data = $response.Content | ConvertFrom-Csv

        # Filter the data by application if specified
        if ($Application) {
            $data = $data | Where-Object { $_.Product -like "*$Application*" }
        }

        # Filter the data by vendor if specified
        if ($Vendor) {
            $data = $data | Where-Object { $_.vendorProject -like "*$Vendor*" }
        }

        # Filter the data by CVE if specified
        if ($CVE) {
            $data = $data | Where-Object { $_.cveID -eq $CVE }
        }

        # Return the filtered data
        return $data
    } catch {
        # Handle any errors that occur during the process
        Write-Error "Failed to retrieve or process data: $_"
    }
}

# Example usage with application filter
Get-CISAKnownVulnerabilities -Application "IPV6"

# Example usage with vendor filter
Get-CISAKnownVulnerabilities -Vendor "Dell"

# Example usage with CVE filter
Get-CISAKnownVulnerabilities -CVE "CVE-2018-0125"