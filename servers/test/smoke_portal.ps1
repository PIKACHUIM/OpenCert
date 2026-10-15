# Smoke test for the portal (storefront) flow.
#
# Verifies the end-to-end slice: product setup -> quote -> login -> order -> order query,
# plus static asset serving and API/protocol path isolation.
#
# Local verification only (not part of production deployment).
# ASCII-only on purpose: Windows PowerShell 5.1 reads .ps1 as ANSI and would mangle non-ASCII text.
param(
    [int]$Port = 1037,
    [string]$Bin = "$env:TEMP\opencert-smoke.exe",
    [string]$WebRoot = ""
)

$ErrorActionPreference = 'Stop'
$base = "http://127.0.0.1:$Port"
$workDir = Join-Path $env:TEMP ("opencert-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

if (-not $WebRoot) {
    $WebRoot = Join-Path $PSScriptRoot '..\front\dist'
}

$env:SERVER_CARD_HOST = '127.0.0.1'
$env:SERVER_CARD_PORT = "$Port"
$env:SERVER_CARD_DB_PATH = Join-Path $workDir 'smoke.db'
$env:SERVER_CARD_WEB_ROOT = (Resolve-Path $WebRoot).Path
$env:SERVER_CARD_JWT_SECRET = 'smoke-test-secret-key-please-ignore-32bytes'
$env:SERVER_CARD_LOG_LEVEL = 'error'

$proc = Start-Process -FilePath $Bin -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $workDir 'out.log') `
    -RedirectStandardError (Join-Path $workDir 'err.log')

$failures = @()
function Check($name, $condition, $detail) {
    if ($condition) {
        Write-Host "  [PASS] $name"
    } else {
        Write-Host "  [FAIL] $name -> $detail"
        $script:failures += $name
    }
}

try {
    # Wait for the server to become ready
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        try { Invoke-RestMethod "$base/api/health" | Out-Null; $ready = $true; break } catch {}
    }
    if (-not $ready) { throw "server did not start within the expected time" }

    Write-Host ""
    Write-Host "[1] Basic endpoints"
    $health = Invoke-RestMethod "$base/api/health"
    Check 'health check' ($health.status -eq 'ok') ($health | ConvertTo-Json -Compress)

    $site = Invoke-RestMethod "$base/api/portal/site"
    Check 'site settings are public' ($null -ne $site.site_name) ($site | ConvertTo-Json -Compress)

    $cats = Invoke-RestMethod "$base/api/portal/categories"
    Check 'five product categories returned' ($cats.items.Count -eq 5) ($cats.items.Count)

    Write-Host ""
    Write-Host "[2] Unpublished products must not leak to the storefront"
    $empty = Invoke-RestMethod "$base/api/portal/products"
    Check 'no products initially' ($empty.total -eq 0) ($empty.total)

    Write-Host ""
    Write-Host "[3] Static assets and API/protocol path isolation"
    $idx = Invoke-WebRequest -UseBasicParsing "$base/"
    Check 'home returns SPA shell' ($idx.Content -match 'id="root"') ($idx.StatusCode)
    $spa = Invoke-WebRequest -UseBasicParsing "$base/console/products"
    Check 'deep link falls back to index.html' ($spa.Content -match 'id="root"') ($spa.StatusCode)
    try {
        Invoke-RestMethod "$base/api/definitely-not-exists" | Out-Null
        Check 'unknown API returns JSON 404' $false 'no error raised'
    } catch {
        $body = $_.ErrorDetails.Message
        Check 'unknown API returns JSON 404' ($body -match 'error') $body
    }

    Write-Host ""
    Write-Host "[4] Admin login and product configuration"
    $login = Invoke-RestMethod "$base/api/auth/login" -Method Post -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = 'admin' } | ConvertTo-Json)
    Check 'admin login' ($null -ne $login.token) ($login | ConvertTo-Json -Compress)

    $h = @{ Authorization = "Bearer $($login.token)" }
    $prod = Invoke-RestMethod "$base/api/portal/admin/products" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{
            code = 'ssl-dv-smoke'; name = 'Smoke Test Certificate'; category = 'ssl'; level = 'dv'
            summary = 'product used to verify the portal flow'
            features = '["domain validation","full chain"]'; highlights = '["test only"]'
            visible = $true; enabled = $true; sort_weight = 1
        } | ConvertTo-Json -Compress)
    Check 'create product' ($prod.code -eq 'ssl-dv-smoke') ($prod | ConvertTo-Json -Compress)

    $sku = Invoke-RestMethod "$base/api/portal/admin/skus" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{
            product_uuid = $prod.uuid; code = 'ssl-dv-smoke-1y'; name = '1 year'
            price_cents = 6800; currency = 'CNY'; stock = 10; min_qty = 1; max_qty = 5
            duration_months = 12; delivery_mode = 'download'; key_types = '["ec256"]'
            san_included = 1; enabled = $true
        } | ConvertTo-Json -Compress)
    Check 'create sku' ($sku.code -eq 'ssl-dv-smoke-1y') ($sku | ConvertTo-Json -Compress)

    Write-Host ""
    Write-Host "[5] Storefront visibility and server-side quote"
    $list = Invoke-RestMethod "$base/api/portal/products"
    Check 'one product visible on storefront' ($list.total -eq 1) ($list.total)

    $quote = Invoke-RestMethod "$base/api/portal/quotes" -Method Post -ContentType 'application/json' `
        -Body (@{ sku_code = 'ssl-dv-smoke-1y'; quantity = 3 } | ConvertTo-Json)
    Check 'quote total = unit price x quantity' ($quote.total_cents -eq 20400) ($quote.total_cents)

    try {
        Invoke-RestMethod "$base/api/portal/quotes" -Method Post -ContentType 'application/json' `
            -Body (@{ sku_code = 'ssl-dv-smoke-1y'; quantity = 99 } | ConvertTo-Json) | Out-Null
        Check 'over-limit quantity rejected' $false 'no error raised'
    } catch { Check 'over-limit quantity rejected' $true '' }

    Write-Host ""
    Write-Host "[6] Order requires login and uses server-side pricing"
    try {
        Invoke-RestMethod "$base/api/portal/orders" -Method Post -ContentType 'application/json' `
            -Body (@{ sku_code = 'ssl-dv-smoke-1y'; quantity = 1 } | ConvertTo-Json) | Out-Null
        Check 'anonymous order rejected' $false 'no error raised'
    } catch { Check 'anonymous order rejected' $true '' }

    $order = Invoke-RestMethod "$base/api/portal/orders" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{
            sku_code = 'ssl-dv-smoke-1y'; quantity = 3
            applicant_email = 'smoke@example.com'
        } | ConvertTo-Json -Compress)
    Check 'order created with public order number' ($order.order_no -like 'CO*') ($order | ConvertTo-Json -Compress)
    Check 'order amount computed by server' ($order.amount_cents -eq 20400) ($order.amount_cents)
    Check 'order starts as pending payment' ($order.status -eq 'pending_payment') ($order.status)
    Check 'no balance frozen on order creation' ($order.frozen_cents -eq 0) ($order.frozen_cents)

    Write-Host ""
    Write-Host "[7] Order queries"
    $mine = Invoke-RestMethod "$base/api/portal/orders" -Headers $h
    Check 'my orders contains the new order' ($mine.total -ge 1) ($mine.total)

    $one = Invoke-RestMethod "$base/api/portal/orders/$($order.order_no)" -Headers $h
    Check 'query own order by order number' ($one.order_no -eq $order.order_no) ($one.order_no)

    Write-Host ""
    Write-Host "[8] Checkout: free order settles, paid order cannot be paid twice"
    $freeSku = Invoke-RestMethod "$base/api/portal/admin/skus" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{
            product_uuid = $prod.uuid; code = 'ssl-dv-smoke-free'; name = 'free trial'
            price_cents = 0; currency = 'CNY'; stock = -1; min_qty = 1; max_qty = 1
            duration_months = 1; delivery_mode = 'download'; key_types = '["ec256"]'
            san_included = 1; enabled = $true
        } | ConvertTo-Json -Compress)
    Check 'create free sku' ($freeSku.code -eq 'ssl-dv-smoke-free') ($freeSku | ConvertTo-Json -Compress)

    $freeOrder = Invoke-RestMethod "$base/api/portal/orders" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{ sku_code = 'ssl-dv-smoke-free'; quantity = 1 } | ConvertTo-Json -Compress)
    Check 'free order created' ($freeOrder.amount_cents -eq 0) ($freeOrder.amount_cents)

    $channels = Invoke-RestMethod "$base/api/portal/payment-channels" -Headers $h
    $balanceChannels = @($channels.items | Where-Object { $_.channel -eq 'balance' })
    Check 'balance channel available' ($balanceChannels.Count -eq 1) ($channels.items | ConvertTo-Json -Compress)

    $pay = Invoke-RestMethod "$base/api/portal/orders/$($freeOrder.order_no)/pay" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{ channel = 'balance' } | ConvertTo-Json -Compress)
    Check 'free order settled immediately' ($pay.settled -eq $true) ($pay | ConvertTo-Json -Compress)

    $paidOrder = Invoke-RestMethod "$base/api/portal/orders/$($freeOrder.order_no)" -Headers $h
    Check 'order becomes paid' ($paidOrder.status -eq 'paid') ($paidOrder.status)

    try {
        Invoke-RestMethod "$base/api/portal/orders/$($freeOrder.order_no)/pay" -Method Post -Headers $h -ContentType 'application/json' `
            -Body (@{ channel = 'balance' } | ConvertTo-Json -Compress) | Out-Null
        Check 'paid order cannot be paid twice' $false 'no error raised'
    } catch { Check 'paid order cannot be paid twice' $true '' }

    $attempt = Invoke-RestMethod "$base/api/portal/orders/$($freeOrder.order_no)/payment" -Headers $h
    Check 'payment attempt recorded' ($attempt.status -eq 'paid') ($attempt.status)

    Write-Host ""
    Write-Host "[9] Public trust center: only explicitly published CAs are exposed"
    $emptyPki = Invoke-RestMethod "$base/api/portal/pki-endpoints"
    Check 'no public CA initially' ($emptyPki.total -eq 0) ($emptyPki.total)

    $ca = Invoke-RestMethod "$base/api/cas" -Method Post -Headers $h -ContentType 'application/json' `
        -Body (@{
            name = 'Smoke Root CA'; key_type = 'ec256'; valid_years = 1
            common_name = 'Smoke Root CA'; organization = 'Smoke Org'; country = 'CN'
        } | ConvertTo-Json -Compress)
    Check 'create CA' ($null -ne $ca.uuid) ($ca | ConvertTo-Json -Compress)

    $stillEmpty = Invoke-RestMethod "$base/api/portal/pki-endpoints"
    Check 'unpublished CA stays hidden' ($stillEmpty.total -eq 0) ($stillEmpty.total)

    try {
        Invoke-WebRequest -UseBasicParsing "$base/api/portal/pki/cas/$($ca.uuid)/chain" | Out-Null
        Check 'unpublished CA chain not downloadable' $false 'no error raised'
    } catch { Check 'unpublished CA chain not downloadable' $true '' }

    Invoke-RestMethod "$base/api/cas/$($ca.uuid)/publish" -Method Put -Headers $h -ContentType 'application/json' `
        -Body (@{ public = $true } | ConvertTo-Json -Compress) | Out-Null
    $pki = Invoke-RestMethod "$base/api/portal/pki-endpoints"
    Check 'published CA appears in trust center' ($pki.total -eq 1) ($pki.total)
    Check 'CRL/OCSP urls generated' (($pki.items[0].crl_url -like '*/crl/*') -and ($pki.items[0].ocsp_url -like '*/ocsp/*')) ($pki.items[0] | ConvertTo-Json -Compress)
    Check 'fingerprint present' ($pki.items[0].fingerprint -like '*:*') ($pki.items[0].fingerprint)

    # application/x-pem-file 不是文本类型，直接落盘再读取，避免编码与类型歧义
    $chainFile = Join-Path $workDir 'chain.pem'
    Invoke-WebRequest -UseBasicParsing "$base/api/portal/pki/cas/$($ca.uuid)/chain" -OutFile $chainFile
    $chainText = (Get-Content $chainFile -Raw)
    Check 'published CA chain downloadable' ($chainText -match 'BEGIN CERTIFICATE') (($chainText | Out-String).Substring(0, [Math]::Min(20, $chainText.Length)))

    try {
        Invoke-RestMethod "$base/api/cas/$($ca.uuid)/publish" -Method Put -ContentType 'application/json' `
            -Body (@{ public = $false } | ConvertTo-Json -Compress) | Out-Null
        Check 'anonymous cannot publish CA' $false 'no error raised'
    } catch { Check 'anonymous cannot publish CA' $true '' }

    Write-Host ""
    Write-Host "[10] Admin endpoints are not public"
    try {
        Invoke-RestMethod "$base/api/portal/admin/products" | Out-Null
        Check 'anonymous admin access rejected' $false 'no error raised'
    } catch { Check 'anonymous admin access rejected' $true '' }
}
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    Write-Host ""
    Write-Host "log dir: $workDir"
    if (Test-Path (Join-Path $workDir 'err.log')) {
        Get-Content (Join-Path $workDir 'err.log') -Tail 5 -ErrorAction SilentlyContinue
    }
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host ("FAILED: " + ($failures -join ', ')) -ForegroundColor Red
    exit 1
}
