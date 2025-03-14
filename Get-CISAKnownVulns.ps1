function Get-CISAKnownVulnerabilities {
    param (
        [string]$CISAcsv = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv',  # URL of the CSV file
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
Get-CISAKnownVulnerabilities -Application "ExampleApp"

# Example usage with vendor filter
Get-CISAKnownVulnerabilities -Vendor "ExampleVendor"

# Example usage with CVE filter
Get-CISAKnownVulnerabilities -CVE "CVE-2021-12345"

# Example usage with all filters
Get-CISAKnownVulnerabilities -Application "ExampleApp" -Vendor "ExampleVendor" -CVE "CVE-2021-12345"