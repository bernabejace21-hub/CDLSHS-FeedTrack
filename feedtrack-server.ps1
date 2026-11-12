<#
  CDLSHS FeedTrack — local backend server
  ----------------------------------------
  Serves the website AND handles authentication so the school
  password never appears in the HTML/JavaScript source.

    · POST /api/auth/login            {email, password}       -> {ok, token, email, name}
    · POST /api/auth/session          {token}                 -> {ok, email, name, role}
    · POST /api/auth/logout           {token}                 -> {ok}
    · POST /api/auth/forgot           {email}                 -> {ok, sentTo, warning?}
    · POST /api/auth/reset            {email, code, password} -> {ok}
    · POST /api/auth/change-password  {token, currentPassword, newPassword} -> {ok}
    · POST /api/account/get           {token}                 -> {ok, user:{name,email,role,created}}
    · POST /api/account/update        {token, name?, email?}  -> {ok, user:{...}}
    · GET  /api/health                                        -> {ok}

  PER-USER REGISTRY (Revision Round 3)
    Every account has its OWN registered e-mail address. Verification
    codes are always sent to the e-mail address that belongs to the
    account that asked for it — never to one fixed address.
      · accounts live in feedtrack-auth-state.json (users map)
      · seeded from the "users" array in feedtrack-server.json
      · passwords are stored as salted PBKDF2 hashes (never plain text)
      · e-mail changes are saved and used for future recovery
    Add or edit accounts in feedtrack-server.json → "users".

  Rules enforced here (server side):
    · only registered accounts may sign in
    · NO sign-up / create-account path exists in the browser
    · verification codes: 6 digits, expire in 10 minutes,
      max 5 wrong attempts, max 5 codes requested per hour
    · login rate-limited to 10 failures per 15 minutes per address
    · passwords / codes are never sent to the browser

  SMTP (real e-mail delivery) is configured in feedtrack-server.json.
  Gmail needs an App Password (2-Step Verification → App passwords).
  Until SMTP credentials are filled in, the code is created and shown
  ON THIS SERVER'S CONSOLE only, and the browser receives an explicit
  warning that no e-mail was sent (never a fake "e-mail sent" claim).

  Run:  powershell -NoProfile -ExecutionPolicy Bypass -File feedtrack-server.ps1
  Then open:  http://localhost:8765/code2.html
#>
param([int]$Port = 0)

# Render injects $PORT; prefer it over the default
if ($env:PORT) { $Port = [int]$env:PORT }

$ErrorActionPreference = 'Stop'
$root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath   = Join-Path $root 'feedtrack-server.json'
$statePath = Join-Path $root 'feedtrack-auth-state.json'

$CODE_TTL_MS      = 10 * 60 * 1000     # verification code valid 10 minutes
$MAX_CODE_ATTEMPT = 5                  # wrong codes before the code is void
$MAX_SENDS_HOUR   = 5                  # codes per address per hour
$MAX_LOGIN_FAIL   = 10                 # failed logins per address per 15 min
$LOGIN_WINDOW_MS  = 15 * 60 * 1000
$SESSION_TTL_MS   = 12 * 60 * 60 * 1000  # signed-in for 12 hours
$PBKDF2_ITER      = 30000              # password hashing cost

# ---------------------------------------------------------------- config
function Load-JsonFile($path, $fallback) {
  try {
    if (Test-Path -LiteralPath $path) {
      $txt = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
      if ($txt.Trim()) { return ($txt | ConvertFrom-Json) }
    }
  } catch { Write-Host "[config] could not read $path - using defaults ($($_.Exception.Message))" }
  return $fallback
}
function Save-JsonFile($path, $obj) {
  $json = $obj | ConvertTo-Json -Depth 12
  [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
}

$defaultCfg = [pscustomobject]@{
  port = 8765
  smtp = [pscustomobject]@{ host = 'smtp.gmail.com'; port = 587; useSsl = $true; user = 'bernabejace21@gmail.com'; pass = ''; from = 'bernabejace21@gmail.com' }
  users = @(
    [pscustomobject]@{ name = 'Jace Bernabe';          email = 'bernabejace21@gmail.com';        role = 'System Owner / Head Advisor'; password = 'CDLSHS2026' }
    [pscustomobject]@{ name = 'Head Advisor';          email = 'headadvisor@cdlshs.edu.ph';      role = 'Head Advisor';                password = 'CDLSHS2026' }
    [pscustomobject]@{ name = 'Rizza Belle Enriquez';  email = 'rizza.enriquez@cdlshs.edu.ph';   role = 'Programme Adviser';           password = 'CDLSHS2026' }
  )
}
$CFG = Load-JsonFile $cfgPath $defaultCfg
if (-not $CFG.port)           { $CFG | Add-Member -NotePropertyName port -NotePropertyValue 8765 -Force }
if (-not $CFG.smtp)           { $CFG | Add-Member -NotePropertyName smtp -NotePropertyValue $defaultCfg.smtp -Force }
if (-not $CFG.users)          { $CFG | Add-Member -NotePropertyName users -NotePropertyValue $defaultCfg.users -Force }
if (-not (Test-Path -LiteralPath $cfgPath)) { Save-JsonFile $cfgPath $CFG }
if ($Port -gt 0) { $CFG.port = $Port }

# ---- Render environment overrides (used when feedtrack-server.json is not committed) ---
if ($env:SMTP_HOST)   { $CFG.smtp.host   = $env:SMTP_HOST }
if ($env:SMTP_PORT)   { $CFG.smtp.port   = [int]$env:SMTP_PORT }
if ($env:SSL)         { $CFG.smtp.useSsl = ([bool]::Parse($env:SSL)) }
if ($env:SMTP_USER)   { $CFG.smtp.user   = $env:SMTP_USER }
if ($env:SMTP_PASS)   { $CFG.smtp.pass   = $env:SMTP_PASS }
if ($env:SMTP_FROM)   { $CFG.smtp.from   = $env:SMTP_FROM }

# ------------------------------------------------------- auth state store
$STATE = Load-JsonFile $statePath ([pscustomobject]@{ sessions = @{}; resets = @{}; loginFails = @{}; sendLog = @{}; users = @{} })
foreach ($p in 'sessions', 'resets', 'loginFails', 'sendLog', 'users') {
  if (-not $STATE.PSObject.Properties[$p] -or $null -eq $STATE.$p) {
    $STATE | Add-Member -NotePropertyName $p -NotePropertyValue (@{}) -Force
  }
}
function Save-State { Save-JsonFile $statePath $STATE }
function Now { [DateTimeOffset]::Now.ToUnixTimeMilliseconds() }

# PSCustomObject <-> hashtable helpers (ConvertFrom-Json gives PSCustomObject)
function Obj-ToMap($o) {
  $m = @{}
  if ($null -eq $o) { return $m }
  if ($o -is [System.Collections.IDictionary]) { return $o }
  foreach ($p in $o.PSObject.Properties) { $m[$p.Name] = $p.Value }
  return $m
}
function Get-Sessions { Obj-ToMap $STATE.sessions }
function Get-Resets   { Obj-ToMap $STATE.resets }
function Get-Fails    { Obj-ToMap $STATE.loginFails }
function Get-SendLog  { Obj-ToMap $STATE.sendLog }
function Get-Users    { Obj-ToMap $STATE.users }

# --------------------------------------------------------------- helpers
function Read-Body($ctx) {
  if ($ctx.Request.HasEntityBody) {
    $sr = New-Object IO.StreamReader($ctx.Request.InputStream, [Text.Encoding]::UTF8)
    try { return $sr.ReadToEnd() } finally { $sr.Close() }
  }
  return ''
}
function Send-Json($ctx, $obj, [int]$code = 200) {
  $json = $obj | ConvertTo-Json -Depth 8 -Compress
  $b = [Text.Encoding]::UTF8.GetBytes($json)
  $ctx.Response.StatusCode = $code
  $ctx.Response.ContentType = 'application/json; charset=utf-8'
  $ctx.Response.Headers.Add('Cache-Control', 'no-store')
  $ctx.Response.ContentLength64 = $b.Length
  $ctx.Response.OutputStream.Write($b, 0, $b.Length)
  $ctx.Response.OutputStream.Close()
}
function Get-Json($raw) {
  if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
  try { return (ConvertFrom-Json -InputObject $raw) } catch { return @{} }
}
function Test-EmailAddress([string]$email) {
  # any real mailbox is allowed: each user registers their OWN address
  # (school addresses and personal Gmail alike)
  return ($email -match '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$')
}
function New-RandomToken {
  return ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N'))
}
function New-RandomCode {
  $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
  $b = New-Object byte[] 6
  $rng.GetBytes($b)
  $sb = New-Object Text.StringBuilder
  foreach ($x in $b) { [void]$sb.Append(($x % 10).ToString()) }
  return $sb.ToString()
}
# --- verification codes are stored SALT+HASHED, never in plaintext ---
function New-RandomSalt([int]$bytes = 24) {
  $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
  $b = New-Object byte[] $bytes
  $rng.GetBytes($b)
  $sb = New-Object Text.StringBuilder
  foreach ($x in $b) { [void]$sb.Append($x.ToString('x2')) }
  return $sb.ToString()
}
function Get-CodeHash([string]$salt, [string]$code) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($salt + '|' + $code))
    $sb = New-Object Text.StringBuilder
    foreach ($x in $h) { [void]$sb.Append($x.ToString('x2')) }
    return $sb.ToString()
  } finally { $sha.Dispose() }
}
function Test-SecretEqual([string]$a, [string]$b) {
  # constant-time compare so a wrong code cannot be guessed byte-by-byte
  if ($null -eq $a -or $null -eq $b) { return $false }
  $x = [Text.Encoding]::UTF8.GetBytes($a)
  $y = [Text.Encoding]::UTF8.GetBytes($b)
  if ($x.Length -ne $y.Length) { return $false }
  $diff = 0
  for ($i = 0; $i -lt $x.Length; $i++) { $diff = $diff -bor ($x[$i] -bxor $y[$i]) }
  return ($diff -eq 0)
}

# -------------------------------------------------- password hashing (PBKDF2)
function New-PasswordHash([string]$password) {
  $salt = New-Object byte[] 16
  $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
  $rng.GetBytes($salt)
  $pbk = New-Object Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $PBKDF2_ITER)
  $hash = $pbk.GetBytes(32)
  return ([Convert]::ToBase64String($salt)) + '$' + ([Convert]::ToBase64String($hash))
}
function Test-PasswordHash([string]$password, [string]$stored) {
  if ([string]::IsNullOrWhiteSpace($stored)) { return $false }
  $parts = $stored -split '\$', 2
  if ($parts.Count -ne 2) { return $false }
  try {
    $salt = [Convert]::FromBase64String($parts[0])
    $pbk = New-Object Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $PBKDF2_ITER)
    $a = $pbk.GetBytes(32)
    $b = [Convert]::FromBase64String($parts[1])
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $diff = $diff -bor ($a[$i] -bxor $b[$i]) }
    return ($diff -eq 0)
  } catch { return $false }
}

# ------------------------------------------------------ user registry
function Sync-SeedUsers {
  # Seed accounts defined in feedtrack-server.json. Existing accounts are
  # NEVER overwritten (a password reset or e-mail change always wins).
  $users = Get-Users
  $changed = $false
  $seedList = @($CFG.users)
  foreach ($u in $seedList) {
    $em = ([string]$u.email).Trim().ToLower()
    if (-not $em) { continue }
    if ($users.ContainsKey($em)) { continue }
    $users[$em] = @{
      name        = [string]$u.name
      email       = $em
      role        = [string]$u.role
      password    = (New-PasswordHash ([string]$u.password))
      created     = (Get-Date).ToString('s')
      pwChanged   = ''
      emailChanged = ''
    }
    $changed = $true
    Write-Host "[users] registered $em" -ForegroundColor DarkGray
  }
  if ($changed) { $STATE.users = $users; Save-State }
}
function Get-User([string]$email) {
  $users = Get-Users
  if ($users.ContainsKey($email)) { return $users[$email] }
  return $null
}
function Set-User([string]$email, $map) {
  $users = Get-Users
  $users[$email] = $map
  $STATE.users = $users
  Save-State
}
function Public-User($u) {
  if ($null -eq $u) { return $null }
  $m = Obj-ToMap $u
  return @{ name = [string]$m.name; email = [string]$m.email; role = [string]$m.role; created = [string]$m.created; pwChanged = [string]$m.pwChanged }
}
function Get-SessionUser($token) {
  if ([string]::IsNullOrWhiteSpace($token)) { return $null }
  $sessions = Get-Sessions
  $s = $sessions[$token]
  if ($null -eq $s) { return $null }
  $exp = 0; try { $exp = [long]$s.exp } catch { $exp = 0 }
  if ($exp -lt (Now)) { $sessions.Remove($token); $STATE.sessions = $sessions; Save-State; return $null }
  return $s
}

# ------------------------------------------------------------------ mail
# Returns $null on success, or an error string.
function Send-CodeMail([string]$to, [string]$code) {
  $s = $CFG.smtp
  $hostOk = $s -and -not [string]::IsNullOrWhiteSpace([string]$s.host)
  $userOk = $s -and -not [string]::IsNullOrWhiteSpace([string]$s.user)
  $passOk = $s -and -not [string]::IsNullOrWhiteSpace([string]$s.pass)
  if (-not ($hostOk -and $userOk -and $passOk)) {
    # No SMTP credentials configured: do NOT pretend an e-mail was sent.
    # The code stays on this server console only (never shown to browsers).
    Write-Host "[mail] SMTP not configured. Verification code for ${to}: $code" -ForegroundColor Yellow
    return 'NO_SMTP'
  }
  try {
    $from = [string]$s.from; if (-not $from) { $from = [string]$s.user }
    $msg = New-Object Net.Mail.MailMessage
    $msg.From = New-Object Net.Mail.MailAddress($from)
    $msg.To.Add($to)
    $msg.Subject = 'CDLSHS FeedTrack - verification code'
    $msg.Body = @"
Crecencia Drucila Lopez Senior High School
School Based Feeding Program - FeedTrack

Your verification code is:

    $code

It expires in 10 minutes. If you did not request this code,
ignore this message and tell the head advisor.
"@
    $msg.IsBodyHtml = $false
    # Gmail and most providers require TLS 1.2 or newer; without this the
    # connection can be dropped mid-handshake on older .NET defaults.
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    $cli = New-Object Net.Mail.SmtpClient([string]$s.host, [int]$s.port)
    $cli.EnableSsl = [bool]$s.useSsl
    $cli.Timeout = 30000
    # Gmail App Passwords are shown as 4 groups of 4, but .NET sends the
    # string verbatim and Gmail answers 535 unless the spaces are removed.
    $pw = [string]$s.pass
    $compact = $pw -replace '\s', ''
    if ($pw -ne $compact -and $compact.Length -eq 16) { $pw = $compact }
    if ($s.user) {
      $cli.Credentials = New-Object Net.NetworkCredential([string]$s.user, $pw)
    }
    $cli.Send($msg)
    $msg.Dispose(); $cli.Dispose()
    Write-Host "[mail] verification code sent to $to" -ForegroundColor Green
    return $null
  } catch {
    # Log the WHOLE exception chain so a delivery failure is diagnosable
    # from the server console (never from the browser).
    $detail = $_.Exception.Message
    $inner  = $_.Exception.InnerException
    while ($null -ne $inner) { $detail = $detail + ' | ' + $inner.Message; $inner = $inner.InnerException }
    Write-Host "[mail] send FAILED for ${to}: $detail" -ForegroundColor Red
    return 'MAIL_FAILED'
  }
}

# ------------------------------------------------------- rate limiting
function Test-EmailRate($map, [string]$email, [int]$max, [long]$windowMs) {
  $arr = @()
  $v = $map[$email]
  if ($null -ne $v) { $arr = @($v) }
  $cut = (Now) - $windowMs
  $arr = @($arr | Where-Object { [long]$_ -gt $cut })
  if ($arr.Count -ge $max) { return $false }
  return $true
}
function Add-EmailRate($map, [string]$email) {
  $arr = @()
  $v = $map[$email]
  if ($null -ne $v) { $arr = @($v) }
  $arr += ,((Now))
  $map[$email] = $arr
}

# --------------------------------------------------------- API handlers
function Handle-Login($ctx, $body) {
  $j = Get-Json $body
  $email = ([string]$j.email).Trim().ToLower()
  $pw    = [string]$j.password

  if (-not (Test-EmailAddress $email)) {
    return Send-Json $ctx @{ ok = $false; error = 'Enter your registered e-mail address.' } 400
  }
  $fails = Get-Fails
  if (-not (Test-EmailRate $fails $email $MAX_LOGIN_FAIL $LOGIN_WINDOW_MS)) {
    return Send-Json $ctx @{ ok = $false; error = 'Too many sign-in attempts. Wait 15 minutes and try again.' } 429
  }
  $u = Get-User $email
  $ok = ($null -ne $u) -and (Test-PasswordHash $pw ([string](Obj-ToMap $u).password))
  if (-not $ok) {
    Add-EmailRate $fails $email
    $STATE.loginFails = $fails
    Save-State
    return Send-Json $ctx @{ ok = $false; error = 'Invalid e-mail address or password.' } 401
  }
  $um = Obj-ToMap $u
  $token = New-RandomToken
  $sessions = Get-Sessions
  $sessions[$token] = @{ email = $email; name = [string]$um.name; role = [string]$um.role; exp = ((Now) + $SESSION_TTL_MS) }
  $STATE.sessions = $sessions
  $fails = Get-Fails; $fails.Remove($email); $STATE.loginFails = $fails
  Save-State
  Write-Host "[auth] signed in: $email"
  Send-Json $ctx @{ ok = $true; token = $token; email = $email; name = [string]$um.name }
}
function Handle-Session($ctx, $body) {
  $j = Get-Json $body
  $token = [string]$j.token
  $s = Get-SessionUser $token
  if ($null -eq $s) { return Send-Json $ctx @{ ok = $false; error = 'Not signed in.' } 401 }
  Send-Json $ctx @{ ok = $true; email = [string]$s.email; name = [string]$s.name; role = [string]$s.role }
}
function Handle-Logout($ctx, $body) {
  $j = Get-Json $body
  $token = [string]$j.token
  $sessions = Get-Sessions
  if ($sessions.ContainsKey($token)) { $sessions.Remove($token); $STATE.sessions = $sessions; Save-State }
  Send-Json $ctx @{ ok = $true }
}
function Handle-Forgot($ctx, $body) {
  $j = Get-Json $body
  $email = ([string]$j.email).Trim().ToLower()
  if (-not (Test-EmailAddress $email)) {
    return Send-Json $ctx @{ ok = $false; error = 'Enter your registered e-mail address.' } 400
  }
  # the code always goes to THIS account's own registered address
  $u = Get-User $email
  if ($null -eq $u) {
    return Send-Json $ctx @{ ok = $false; error = 'No account is registered with that e-mail address. Contact the head advisor to register your account.' } 404
  }
  $sendLog = Get-SendLog
  if (-not (Test-EmailRate $sendLog $email $MAX_SENDS_HOUR 3600000)) {
    return Send-Json $ctx @{ ok = $false; error = 'Too many code requests for this address. Try again later.' } 429
  }
  $code = New-RandomCode
  $salt = New-RandomSalt
  $resets = Get-Resets
  # only a salted SHA-256 of the code reaches disk; the plaintext exists in
  # memory and inside the outgoing e-mail only
  $resets[$email] = @{ codeHash = (Get-CodeHash $salt $code); salt = $salt
                       exp = ((Now) + $CODE_TTL_MS); attempts = 0; sent = (Now) }
  $STATE.resets = $resets
  Add-EmailRate $sendLog $email
  $STATE.sendLog = $sendLog
  Save-State

  $err = Send-CodeMail $email $code
  if ($err -eq 'MAIL_FAILED') {
    # Honest failure: nothing was delivered, so no code may remain usable.
    $resets = Get-Resets
    if ($null -ne $resets[$email]) { $resets.Remove($email); $STATE.resets = $resets; Save-State }
    return Send-Json $ctx @{ ok = $false; error = 'The verification e-mail could not be delivered, so no code was issued. Please try again later or ask the head advisor to reset your password.' } 502
  }
  Write-Host "[auth] verification code issued for $email (valid 10 minutes)"
  if ($err -eq 'NO_SMTP') {
    # honest feedback: the code exists but no e-mail has left the server yet
    return Send-Json $ctx @{ ok = $true; sentTo = $email; warning = 'SMTP e-mail is not configured yet, so no e-mail was sent. The code is shown on the server console (feedtrack-server.ps1 window).' }
  }
  Send-Json $ctx @{ ok = $true; sentTo = $email }
}
function Handle-Reset($ctx, $body) {
  $j = Get-Json $body
  $email    = ([string]$j.email).Trim().ToLower()
  $code     = ([string]$j.code).Trim()
  $newPw    = [string]$j.password

  if (-not (Test-EmailAddress $email)) {
    return Send-Json $ctx @{ ok = $false; error = 'Enter your registered e-mail address.' } 400
  }
  if ($newPw.Length -lt 6) {
    return Send-Json $ctx @{ ok = $false; error = 'The new password must be at least 6 characters.' } 400
  }
  $u = Get-User $email
  if ($null -eq $u) {
    return Send-Json $ctx @{ ok = $false; error = 'No account is registered with that e-mail address.' } 404
  }
  $resets = Get-Resets
  $r = $resets[$email]
  if ($null -eq $r) {
    return Send-Json $ctx @{ ok = $false; error = 'Request a verification code first.' } 400
  }
  $exp = 0; $att = 0
  try { $exp = [long]$r.exp } catch { $exp = 0 }
  try { $att = [int]$r.attempts } catch { $att = 0 }
  if ($exp -lt (Now)) {
    $resets.Remove($email); $STATE.resets = $resets; Save-State
    return Send-Json $ctx @{ ok = $false; error = 'The verification code has expired. Request a new one.' } 400
  }
  if ($att -ge $MAX_CODE_ATTEMPT) {
    $resets.Remove($email); $STATE.resets = $resets; Save-State
    return Send-Json $ctx @{ ok = $false; error = 'Too many wrong attempts for this code. Request a new one.' } 429
  }
  $okCode = $false
  if ($r.codeHash) {
    $okCode = Test-SecretEqual ([string]$r.codeHash) (Get-CodeHash ([string]$r.salt) $code)
  } elseif ($r.code) {
    $okCode = Test-SecretEqual ([string]$r.code) $code
  }
  if (-not $okCode) {
    $r.attempts = $att + 1
    $resets[$email] = $r
    $STATE.resets = $resets; Save-State
    $left = $MAX_CODE_ATTEMPT - ($att + 1)
    return Send-Json $ctx @{ ok = $false; error = "Incorrect verification code. $left attempt(s) left before a new code is required." } 400
  }
  # success: replace ONLY this account's password (other users are untouched)
  $um = Obj-ToMap $u
  $um.password    = (New-PasswordHash $newPw)
  $um.pwChanged   = (Get-Date).ToString('s')
  Set-User $email $um
  $resets.Remove($email); $STATE.resets = $resets
  $fails = Get-Fails; $fails.Remove($email); $STATE.loginFails = $fails
  Save-State
  Write-Host "[auth] password reset for $email"
  Send-Json $ctx @{ ok = $true }
}
function Handle-ChangePassword($ctx, $body) {
  $j = Get-Json $body
  $token   = [string]$j.token
  $cur     = [string]$j.currentPassword
  $newPw   = [string]$j.newPassword
  $s = Get-SessionUser $token
  if ($null -eq $s) { return Send-Json $ctx @{ ok = $false; error = 'Your session has expired. Sign in again.' } 401 }
  $email = [string]$s.email
  $u = Get-User $email
  if ($null -eq $u) { return Send-Json $ctx @{ ok = $false; error = 'Account not found.' } 404 }
  $um = Obj-ToMap $u
  if (-not (Test-PasswordHash $cur ([string]$um.password))) {
    return Send-Json $ctx @{ ok = $false; error = 'The current password is incorrect.' } 400
  }
  if ($newPw.Length -lt 6) {
    return Send-Json $ctx @{ ok = $false; error = 'The new password must be at least 6 characters.' } 400
  }
  if ($newPw -ceq $cur) {
    return Send-Json $ctx @{ ok = $false; error = 'The new password must be different from the current one.' } 400
  }
  $um.password  = (New-PasswordHash $newPw)
  $um.pwChanged = (Get-Date).ToString('s')
  Set-User $email $um
  Write-Host "[auth] password changed for $email"
  Send-Json $ctx @{ ok = $true }
}
function Handle-AccountGet($ctx, $body) {
  $j = Get-Json $body
  $s = Get-SessionUser ([string]$j.token)
  if ($null -eq $s) { return Send-Json $ctx @{ ok = $false; error = 'Your session has expired. Sign in again.' } 401 }
  $u = Get-User ([string]$s.email)
  if ($null -eq $u) { return Send-Json $ctx @{ ok = $false; error = 'Account not found.' } 404 }
  Send-Json $ctx @{ ok = $true; user = (Public-User $u) }
}
function Handle-AccountUpdate($ctx, $body) {
  $j = Get-Json $body
  $s = Get-SessionUser ([string]$j.token)
  if ($null -eq $s) { return Send-Json $ctx @{ ok = $false; error = 'Your session has expired. Sign in again.' } 401 }

  $oldEmail = [string]$s.email
  $u = Get-User $oldEmail
  if ($null -eq $u) { return Send-Json $ctx @{ ok = $false; error = 'Account not found.' } 404 }
  $um = Obj-ToMap $u

  $newName  = ([string]$j.name).Trim()
  $newEmail = ([string]$j.email).Trim().ToLower()
  if ($newName.Length -lt 2) { return Send-Json $ctx @{ ok = $false; error = 'Enter your full name (at least 2 characters).' } 400 }
  if (-not (Test-EmailAddress $newEmail)) { return Send-Json $ctx @{ ok = $false; error = 'Enter a valid e-mail address.' } 400 }

  if ($newEmail -ne $oldEmail) {
    $users = Get-Users
    if ($users.ContainsKey($newEmail)) {
      return Send-Json $ctx @{ ok = $false; error = 'Another account already uses that e-mail address.' } 409
    }
  }

  $um.name = $newName
  $changedEmail = ($newEmail -ne $oldEmail)
  if ($changedEmail) {
    $um.email       = $newEmail
    $um.emailChanged = (Get-Date).ToString('s')
  }

  if ($changedEmail) {
    # move the account to its new key and keep every live session pointing at it
    $users = Get-Users
    $users.Remove($oldEmail)
    $users[$newEmail] = $um
    $STATE.users = $users
    $sessions = Get-Sessions
    foreach ($k in @($sessions.Keys)) {
      if ([string]$sessions[$k].email -eq $oldEmail) {
        $ses = Obj-ToMap $sessions[$k]
        $ses.email = $newEmail; $ses.name = $newName
        $sessions[$k] = $ses
      }
    }
    $STATE.sessions = $sessions
    Save-State
    Write-Host "[account] $oldEmail changed e-mail to $newEmail"
  } else {
    $sessions = Get-Sessions
    foreach ($k in @($sessions.Keys)) {
      if ([string]$sessions[$k].email -eq $oldEmail) {
        $ses = Obj-ToMap $sessions[$k]
        $ses.name = $newName
        $sessions[$k] = $ses
      }
    }
    $STATE.sessions = $sessions
    Set-User $oldEmail $um
    Write-Host "[account] $oldEmail updated profile"
  }

  Send-Json $ctx @{ ok = $true; user = (Public-User $um); emailChanged = $changedEmail }
}

# -------------------------------------------------------- static serving
$MIME = @{
  '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'
  '.css'  = 'text/css; charset=utf-8';  '.json' = 'application/json; charset=utf-8'
  '.jpg'  = 'image/jpeg';               '.jpeg' = 'image/jpeg'
  '.png'  = 'image/png';                '.gif'  = 'image/gif'
  '.svg'  = 'image/svg+xml';            '.ico'  = 'image/x-icon'
  '.webp' = 'image/webp';               '.woff2'= 'font/woff2'
  '.xlsx' = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
}
# never hand these to a browser
$BLOCK_EXT   = @('.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.exe', '.sh', '.py', '.ini')
$BLOCK_NAMES = @('feedtrack-server.json', 'feedtrack-auth-state.json')

function Send-File($ctx, $path) {
  $ext = [IO.Path]::GetExtension($path).ToLower()
  $bytes = [IO.File]::ReadAllBytes($path)
  $ctx.Response.StatusCode = 200
  $ctx.Response.ContentType = $MIME[$ext]
  if (-not $ctx.Response.ContentType) { $ctx.Response.ContentType = 'application/octet-stream' }
  $ctx.Response.ContentLength64 = $bytes.Length
  $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $ctx.Response.OutputStream.Close()
}
function Send-Text($ctx, [string]$text, [int]$code, [string]$ctype) {
  $b = [Text.Encoding]::UTF8.GetBytes($text)
  $ctx.Response.StatusCode = $code
  $ctx.Response.ContentType = $ctype
  $ctx.Response.ContentLength64 = $b.Length
  $ctx.Response.OutputStream.Write($b, 0, $b.Length)
  $ctx.Response.OutputStream.Close()
}

# ----------------------------------------------------------------- listen
Sync-SeedUsers
if (-not $Port) { $Port = [int]$CFG.port }
$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
try {
  $listener.Start()
} catch {
  Write-Host "Could not bind http://+:$Port/ - $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "Another server may already be running (stop it first), or pass -Port <number>." -ForegroundColor Yellow
  exit 1
}
Write-Host "CDLSHS FeedTrack server running on http://0.0.0.0:$Port/" -ForegroundColor Cyan
Write-Host "Open  http://0.0.0.0:$Port/code2.html" -ForegroundColor Cyan
$registered = (Get-Users).Count
Write-Host "$registered registered account(s) — each with its own e-mail address." -ForegroundColor Cyan
if ([string]::IsNullOrWhiteSpace([string]$CFG.smtp.pass)) {
  Write-Host "SMTP not configured yet - edit feedtrack-server.json (smtp.pass) to e-mail real codes." -ForegroundColor Yellow
  Write-Host "Gmail: enable 2-Step Verification, then create an App Password and paste it into smtp.pass." -ForegroundColor Yellow
}
Write-Host "Passwords and verification codes are held ONLY by this server." -ForegroundColor DarkGray

while ($listener.IsListening) {
  $ctx = $null
  try { $ctx = $listener.GetContext() } catch { break }
  try {
    $path = $ctx.Request.Url.AbsolutePath
    if ($path -like '/api/*') {
      $raw = if ($ctx.Request.HttpMethod -eq 'POST') { Read-Body $ctx } else { '' }
      $isPost = ($ctx.Request.HttpMethod -eq 'POST')
      $route = $null
      $handled = $false
      switch -Regex ($path) {
        '^/api/health$'               { Send-Json $ctx @{ ok = $true; app = 'CDLSHS FeedTrack' }; $handled = $true }
        '^/api/auth/login$'           { $route = 'login' }
        '^/api/auth/session$'         { $route = 'session' }
        '^/api/auth/logout$'          { $route = 'logout' }
        '^/api/auth/forgot$'          { $route = 'forgot' }
        '^/api/auth/reset$'           { $route = 'reset' }
        '^/api/auth/change-password$' { $route = 'change-password' }
        # the browser always calls /api/auth/<action>, so the account routes
        # accept both spellings (the bare /api/account/* form is kept too)
        '^/api/account/get$'          { $route = 'account-get' }
        '^/api/account/update$'       { $route = 'account-update' }
        '^/api/auth/account/get$'     { $route = 'account-get' }
        '^/api/auth/account/update$'  { $route = 'account-update' }
      }
      if ($handled) { continue }
      if ($null -eq $route) { Send-Json $ctx @{ ok = $false; error = 'Unknown endpoint' } 404; continue }
      if (-not $isPost) { Send-Json $ctx @{ ok = $false; error = 'Method not allowed' } 405; continue }
      switch ($route) {
        'login'           { Handle-Login          $ctx $raw }
        'session'         { Handle-Session        $ctx $raw }
        'logout'          { Handle-Logout         $ctx $raw }
        'forgot'          { Handle-Forgot         $ctx $raw }
        'reset'           { Handle-Reset          $ctx $raw }
        'change-password' { Handle-ChangePassword $ctx $raw }
        'account-get'     { Handle-AccountGet     $ctx $raw }
        'account-update'  { Handle-AccountUpdate  $ctx $raw }
      }
      continue
    }

    # ---- static files ----
    $rel = [Uri]::UnescapeDataString($path.TrimStart('/'))
    if (-not $rel -or $rel.EndsWith('/')) { $rel = $rel + 'code2.html' }
    if ([string]::IsNullOrWhiteSpace($rel)) { $rel = 'code2.html' }

    $full = [IO.Path]::GetFullPath((Join-Path $root $rel))
    $rootFull = [IO.Path]::GetFullPath($root)
    if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
      Send-Text $ctx 'Forbidden' 403 'text/plain; charset=utf-8'; continue
    }
    $name = [IO.Path]::GetFileName($full)
    $ext  = [IO.Path]::GetExtension($full).ToLower()
    if ($BLOCK_EXT -contains $ext -or $BLOCK_NAMES -contains $name) {
      Send-Text $ctx 'Not found' 404 'text/plain; charset=utf-8'; continue
    }
    if ([IO.File]::Exists($full)) {
      Send-File $ctx $full
    } elseif ([IO.Directory]::Exists($full)) {
      $idx = Join-Path $full 'index.html'
      if ([IO.File]::Exists($idx)) { Send-File $ctx $idx }
      else { Send-Text $ctx 'Not found' 404 'text/plain; charset=utf-8' }
    } else {
      Send-Text $ctx 'Not found' 404 'text/plain; charset=utf-8'
    }
  } catch {
    try { Send-Text $ctx 'Server error' 500 'text/plain; charset=utf-8' } catch {}
    Write-Host "[error] $($_.Exception.Message)" -ForegroundColor Red
  }
}
