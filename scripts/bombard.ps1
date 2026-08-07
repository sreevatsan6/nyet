# bombard.ps1 - sends a burst of nslookup queries to local DNS (127.0.0.1)
# for smoke-testing that nyet is actually intercepting/sinkholing traffic.
# Not exhaustive by design -- add your own domains below if you want more
# coverage, but keep additions generic (no device IDs, session IDs, or
# ISP/account-specific hostnames).

$count = 50
$domains = @(
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "graph.facebook.com",
    "incoming.telemetry.mozilla.org",
    "scorecardresearch.com",
    "example.com"
)

Write-Host "Spamming $count nslookup queries to 127.0.0.1 ..."
for ($i = 0; $i -lt $count; $i++) {
    $domain = $domains[$i % $domains.Count]
    nslookup $domain 127.0.0.1 2>&1 | Out-Null
    if ($i % 20 -eq 0) { Write-Host "Completed $i queries..." }
}
