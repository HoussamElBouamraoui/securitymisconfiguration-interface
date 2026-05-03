$body = @{
    target = "https://cryptomh.vercel.app"
} | ConvertTo-Json

$headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NzYwNzA4MDEsImV4cCI6MTc3NjA3NDQwMSwidHlwZSI6ImFjY2Vzc190b2tlbiIsInVzZXJfaWQiOjEsInJvbGUiOiJhZG1pbiJ9.sDTnRapCCtroCI2zkqd33X-AAMDH-dX4WANuuS38TWw"
}

try {
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/scan" -Method POST -Headers $headers -Body $body
    $response | ConvertTo-Json -Depth 10
} catch {
    Write-Host "Error: $($_.Exception.Message)"
    Write-Host "Status: $($_.Exception.Response.StatusCode)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $errorBody = $reader.ReadToEnd()
        Write-Host "Response body: $errorBody"
    }
}
