<#
.SYNOPSIS
    Queries Avalara's public tax rate lookup endpoint for U.S. sales tax rates.

.DESCRIPTION
    Reverse-engineered from the Avalara Tax Rate Calculator at:
    https://www.avalara.com/taxrates/en/calculator.html

    Uses the same unauthenticated backend endpoint the web calculator calls.
    NO API key, account, or authentication required.

    Supports two lookup modes:
      1. By street address (lineAddress1 + city + region)
      2. By latitude/longitude coordinates

    Returns combined sales tax rate with full jurisdiction breakdown
    (State, County, City, Special districts).

.PARAMETER LineAddress1
    Street address line (e.g., "100 Ravine Ln NE").

.PARAMETER City
    City name (e.g., "Bainbridge Island").

.PARAMETER Region
    Two-letter state code (e.g., "WA", "NY", "CA").

.PARAMETER Latitude
    Decimal latitude for coordinate-based lookup.

.PARAMETER Longitude
    Decimal longitude for coordinate-based lookup.

.PARAMETER Amount
    Optional dollar amount to calculate tax on.

.PARAMETER Raw
    Return the raw API response object instead of formatted output.

.EXAMPLE
    # Basic address lookup
    .\Get-SalesTaxRate.ps1 -LineAddress1 "100 Ravine Ln NE" -City "Bainbridge Island" -Region "WA"

.EXAMPLE
    # Calculate tax on a specific dollar amount
    .\Get-SalesTaxRate.ps1 -LineAddress1 "350 5th Ave" -City "New York" -Region "NY" -Amount 1500.00

.EXAMPLE
    # Coordinate-based lookup (Seattle)
    .\Get-SalesTaxRate.ps1 -Latitude 47.6062 -Longitude -122.3321

.EXAMPLE
    # Batch lookup from CSV
    Import-Csv .\addresses.csv | ForEach-Object {
        .\Get-SalesTaxRate.ps1 -LineAddress1 $_.Street -City $_.City -Region $_.State
    } | Export-Csv .\tax_rates.csv -NoTypeInformation

.EXAMPLE
    # Raw output for scripting
    $result = .\Get-SalesTaxRate.ps1 -LineAddress1 "1 Microsoft Way" -City "Redmond" -Region "WA" -Raw
    $result.totalTax  # 10.2 (percent)

.NOTES
    Endpoint : https://avatax-prod.avlr.net/avalara/avatax/getresponse
    Auth     : None required (public endpoint)
    Source   : Reverse-engineered from Avalara's free tax calculator JS
    Rates    : Returned as percentages (e.g., 10.2 = 10.2%)

    This uses a public-facing, unauthenticated endpoint. Avalara could change
    or restrict it at any time. For production/high-volume use, consider their
    official AvaTax API with proper credentials.
#>

[CmdletBinding(DefaultParameterSetName = 'Address')]
param(
    [Parameter(ParameterSetName = 'Address', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Street', 'Address', 'Line1')]
    [string]$LineAddress1,

    [Parameter(ParameterSetName = 'Address', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$City,

    [Parameter(ParameterSetName = 'Address', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('State')]
    [ValidatePattern('^[A-Za-z]{2}$')]
    [string]$Region,

    [Parameter(ParameterSetName = 'Coordinates', Mandatory = $true)]
    [ValidateRange(-90, 90)]
    [double]$Latitude,

    [Parameter(ParameterSetName = 'Coordinates', Mandatory = $true)]
    [ValidateRange(-180, 180)]
    [double]$Longitude,

    [Parameter()]
    [ValidateRange(0.01, [double]::MaxValue)]
    [decimal]$Amount,

    [Parameter()]
    [switch]$Raw
)

begin {
    # ── Configuration ──────────────────────────────────────────────────
    # This is the same endpoint the Avalara web calculator calls.
    # Discovered by inspecting clientlib-avatax.js on the calculator page.
    $BaseUrl = 'https://avatax-prod.avlr.net/avalara/avatax/getresponse'

    # Enforce TLS 1.2 (required by endpoint)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

process {
    # ── Build query parameters based on lookup mode ────────────────────
    if ($PSCmdlet.ParameterSetName -eq 'Address') {
        # Address-based lookup: lineAddress1, city, region
        $queryParams = @(
            "lineAddress1=$([uri]::EscapeDataString($LineAddress1))"
            "city=$([uri]::EscapeDataString($City))"
            "region=$([uri]::EscapeDataString($Region.ToUpper()))"
        ) -join '&'

        $locationLabel = "$LineAddress1, $City, $($Region.ToUpper())"
    }
    else {
        # Coordinate-based lookup: latitude, longitude
        $queryParams = @(
            "latitude=$Latitude"
            "longitude=$Longitude"
        ) -join '&'

        $locationLabel = "Lat $Latitude, Lon $Longitude"
    }

    $uri = "${BaseUrl}?${queryParams}"
    Write-Verbose "Request URI: $uri"

    # ── Make the API call ──────────────────────────────────────────────
    # The endpoint requires Origin and Referer headers from avalara.com
    try {
        $webResponse = Invoke-RestMethod -Uri $uri -Method Get -Headers @{
            'Accept'     = 'application/json, text/plain, */*'
            'Origin'     = 'https://www.avalara.com'
            'Referer'    = 'https://www.avalara.com/'
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        } -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to query Avalara tax rate endpoint: $_"
        return
    }

    # ── Parse response ─────────────────────────────────────────────────
    # Response may be double-JSON-encoded (string containing JSON)
    if ($webResponse -is [string]) {
        try {
            $taxData = $webResponse | ConvertFrom-Json
        }
        catch {
            Write-Error "Failed to parse API response: $webResponse"
            return
        }
    }
    else {
        $taxData = $webResponse
    }

    # Validate response status
    if ($taxData.status -ne 200) {
        Write-Error "Avalara returned status $($taxData.status) for location: $locationLabel"
        return
    }

    # ── Return raw object if requested ─────────────────────────────────
    if ($Raw) {
        return $taxData
    }

    # ── Build formatted output object ──────────────────────────────────
    $result = [PSCustomObject]@{
        Location     = $locationLabel
        TotalRate    = $taxData.totalTax                             # e.g., 10.2
        TotalRateFmt = "{0:N2}%" -f $taxData.totalTax               # e.g., "10.20%"
        Jurisdictions = @(
            foreach ($j in $taxData.summary) {
                [PSCustomObject]@{
                    Name = $j.jurisName
                    Type = $j.jurisType
                    Rate = $j.taxCalculated
                    Pct  = "{0:N2}%" -f $j.taxCalculated
                }
            }
        )
    }

    # ── Optionally calculate tax on a dollar amount ────────────────────
    if ($PSBoundParameters.ContainsKey('Amount')) {
        $taxAmount   = [math]::Round($Amount * ($taxData.totalTax / 100), 2)
        $totalAmount = $Amount + $taxAmount

        $result | Add-Member -NotePropertyName 'ItemAmount'  -NotePropertyValue $Amount
        $result | Add-Member -NotePropertyName 'TaxAmount'   -NotePropertyValue $taxAmount
        $result | Add-Member -NotePropertyName 'TotalAmount' -NotePropertyValue $totalAmount
    }

    # ── Display formatted results ──────────────────────────────────────
    Write-Host ""
    Write-Host "--- Sales Tax Rate Lookup ---" -ForegroundColor Cyan
    Write-Host "Location:   $($result.Location)"
    Write-Host "Total Rate: $($result.TotalRateFmt)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Jurisdiction Breakdown:" -ForegroundColor Cyan
    $result.Jurisdictions | Format-Table -Property Name, Type, Pct -AutoSize | Out-Host

    if ($PSBoundParameters.ContainsKey('Amount')) {
        Write-Host "--- Tax Calculation ---" -ForegroundColor Cyan
        Write-Host ("  Item Amount:  {0,12:C2}" -f $result.ItemAmount)
        Write-Host ("  Sales Tax:    {0,12:C2}" -f $result.TaxAmount) -ForegroundColor Yellow
        Write-Host ("  Total:        {0,12:C2}" -f $result.TotalAmount) -ForegroundColor Green
        Write-Host ""
    }

    # Return the object for pipeline use
    return $result
}
