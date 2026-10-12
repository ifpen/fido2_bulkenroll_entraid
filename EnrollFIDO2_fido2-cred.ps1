###region utility functions

###taken from https://github.com/rmbolger/Posh-ACME/blob/main/Posh-ACME/Private/ConvertTo-Base64Url.ps1 (MIT, Commit 13367d2)
function ConvertTo-Base64Url {
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(ParameterSetName='String',Mandatory,Position=0,ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(ParameterSetName='String')]
        [switch]$FromBase64,
        [Parameter(ParameterSetName='Bytes',Mandatory,Position=0)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    Process {
        if (-not $FromBase64) {
            # get a byte array from the input string
            if ($PSCmdlet.ParameterSetName -eq 'String') {
                $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
            }
            # standard base64 encoder
            $s = [Convert]::ToBase64String($Bytes)
        } else {
            # $Text is already Base64 encoded, we just need the Url'ized version
            $s = $Text
        }
        # remove trailing '='s
        $s = $s.Split('=')[0]
        # 62nd and 63rd char of encoding
        $s = $s.Replace('+','-').Replace('/','_')
        return $s
    }
}

#https://stackoverflow.com/a/10939609 (changed to only allow integers
function Is-Numeric ($Value) {
    return $Value -match "^[\d]+$"
}

# not publicly exported therefore taken unmodified
# from (DS-Internals.Passkeys v1.0.3, MIT) https://github.com/MichaelGrafnetter/webauthn-interop
function Get-MgGraphEndpoint {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    [Microsoft.Graph.PowerShell.Authentication.AuthContext] $context = Get-MgContext -ErrorAction Stop

    if($null -ne $context) {
        return (Get-MgEnvironment -Name $context.Environment -ErrorAction Stop).GraphEndpoint
    }
    else {
        # TODO: PS Error Record ($PSCmdlet.ThrowTerminatingError())
        throw 'Not connected to Microsoft Graph.'
    }
}

###endregion

###region CBOR handling

function cbor-build-len($type, $len){
	if($len -lt 24) { # less than 24 -> into the type byte itself
		return (@($type+$len))
	}
	elseif($len -lt 256) { # more than 24 but within 1 Byte -> Add 24 to type, then add the byte
		$full=@()
		$full+=@($type+24)
		$full+=@($len)
		return $full
	}
	elseif($len -lt 65536) { # 2 bytes -> add 25 and the length bytes individually (Big Endian)
		$full=@()
		$full+=@($type+25)
		$full+=@([int][Math]::Floor($len / 256))
		$full+=@($len%256)
		return $full
	}
	else {
		exit #processing of larger sizes is currently not required
	}
}

function str-to-bytes($str) { #get UTF-8 Byte array for CBOR Text
	return ([system.Text.Encoding]::UTF8.GetBytes($str))
}

function cbor-build-text($str) {
	$typetxt=96
	#get text as UTF-8 Bytes and CBOR Type/length data
	$strarray=str-to-bytes($str)
	$cborlen=cbor-build-len $typetxt $strarray.Count
	$full = @()
	$full += $cborlen 
	$full += $strarray
	return $full
}

function cbor-build-bytes($b64) { #bytes from base64
	$typebytes=64
	$bytearray=[System.Convert]::FromBase64String($b64)
	#get cbor type and length bytes
	$cborlen=cbor-build-len $typebytes $bytearray.Count
	#prepare empty array to add type, length and data
	$full = @()
	$full += $cborlen
	$full += $bytearray
	return $full
}

function build-att-object($sig, $authdata, $x5c, $alg="es256") {
	#cbor base types
	$map=160
	$array=128
	$neg=32
	$ecdsamod=6 #-7 -> in cbor negative = (-1) - argument
	
	if($alg -ne "es256") {
		Exit # Let's not deal with this for now
	}
	
	$cbor= @() #empty array
	Write-Host "preparing CBOR..."
	#map of 3 (format, statement, authdata)
	$cbor += cbor-build-len $map 3
	#fmt:packed
	$cbor += cbor-build-text("fmt")
	$cbor += cbor-build-text("packed")
	#attestation statement map (alg,sig,x5c)
	$cbor += cbor-build-text("attStmt") 
	$cbor += cbor-build-len $map 3
	#alg:-7 (ES256, add more later maybe)
	$cbor += cbor-build-text("alg") 
	$cbor += @(38)
	#attetstation signature
	$cbor += cbor-build-text("sig")
	$cbor += cbor-build-bytes($sig)
	#x5c (attestation cert)
	$cbor += cbor-build-text("x5c")
	#currently no support for Intermediates, therefore a fixed array of 1
	$cbor += cbor-build-len $array 1
	$cbor += cbor-build-bytes($x5c)
	#authdata (already with cbor typing and length data, so can just b64 decode and append, after the label
	$cbor += cbor-build-text("authData")
	$cbor += [System.Convert]::FromBase64String($authdata)
	#convert everything to Base64 for sending out
	$cborb64 = [System.Convert]::ToBase64String($cbor)
	
	return $cborb64
}

###endregion



# Function to check and install a module if not present
function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$InstallCommand = $ModuleName # Defaults to the same name as the module
    )
    # Check if the module is installed
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Output "Module '$ModuleName' is not installed. Installing..."
        try {
            Install-Module -Name $InstallCommand -Scope CurrentUser -Force -AllowClobber
            Write-Output "Module '$ModuleName' installed successfully."
        } catch {
            Write-Error "Failed to install module '$ModuleName': $_"
        }
    } else {
        Write-Output "Module '$ModuleName' is already installed."
    }
}

# Ensure Connect-MgGraph is installed
Ensure-Module -ModuleName "Microsoft.Graph" -InstallCommand "Microsoft.Graph"

# Ensure dsinternals.passkeys is installed
Ensure-Module -ModuleName "DSInternals.PassKeys"


# Generation de PIN aleatoire 8 chiffres (CSPRNG, tirage AVEC remise)
# Corrige le bug d'entropie de l'original (Get-Random -Count = sans remise)
function New-RandomPin {
    [OutputType([string])]
    param([int] $Length = 8)
    # ::Create()/GetBytes : compatible Windows PowerShell 5.1 (.NET Framework)
    # (la methode statique ::Fill() n'existe qu'a partir de .NET Core / PS 7)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    do {
        $digits = New-Object System.Collections.Generic.List[int]
        $b = New-Object byte[] 1
        while ($digits.Count -lt $Length) {
            $rng.GetBytes($b)
            if ($b[0] -lt 250) { $digits.Add($b[0] % 10) }  # rejet anti-biais modulo
        }
        $pin = -join $digits

        # Filtres de complexite PIN+
        $isSequential = $false
        for ($i = 0; $i -le ($pin.Length - 6); $i++) {
            $slice = $pin.Substring($i, 6)
            if ('0123456789'.Contains($slice) -or '9876543210'.Contains($slice)) {
                $isSequential = $true; break
            }
        }
        $hasRepeatedDigits = $pin -match '(\d)\1{3,}'
        $charArray = $pin.ToCharArray()
        [Array]::Reverse($charArray)
        $isPalindrome = ($pin -eq (-join $charArray))
    } while ($isSequential -or $hasRepeatedDigits -or $isPalindrome)
    $rng.Dispose()
    return $pin
}


# taken from Register-Passkey https://github.com/MichaelGrafnetter/webauthn-interop
# (DSInternals.Passkeys v1.0.3, MIT)
# sending finalized Passkey data to API, cut down to only do the sending to API, and relaxed typing of Passkey for easier access
function Graph-Register-Custom-Passkey
{
    [CmdletBinding()]
    [OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphFido2AuthenticationMethod])]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('User')]
        [string] $UserId, #upn
		#json string instead for easier access from outside
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String] $Passkey
    )
    process
    {
		## send finished passkey to API
		[string] $endpoint = Get-MgGraphEndpoint
		# Generate the user-specific URL, e.g., https://graph.microsoft.com/beta/users/af4cf208-16e0-429d-b574-2a09c5f30dea/authentication/fido2Methods
		[string] $registrationUrl = '{0}/beta/users/{1}/authentication/fido2Methods' -f $endpoint, [uri]::EscapeDataString($UserId)
		
		[string] $response = Invoke-MgGraphRequest `
								-Method POST `
								-Uri $registrationUrl `
								-OutputType Json `
								-ContentType 'application/json' `
								-Body $Passkey
								#-Body $Passkey.ToString()

		return [Microsoft.Graph.PowerShell.Models.MicrosoftGraphFido2AuthenticationMethod]::FromJsonString($response)
    }
}

# taken from New-Passkey https://github.com/MichaelGrafnetter/webauthn-interop (DS-Internals.Passkeys v1.0.3, MIT)
# created nearly from Scratch to bypass Windows Hello
function CTAP-Create-Custom-Passkey
{
    [CmdletBinding()]
    [OutputType([DSInternals.Win32.WebAuthn.MicrosoftGraphWebauthnAttestationResponse])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [DSInternals.Win32.WebAuthn.MicrosoftGraphWebauthnCredentialCreationOptions]
        $Options,

        [Parameter(Mandatory = $true)]
        [string] $DisplayName,
		
		[Parameter(Mandatory = $true)]
        [string] $pin
    )

    process
    {
        try {
			
			#get Relying Party ID, user name/ID 
			$rpid = $Options.PublicKeyOptions.RelyingParty.id
			
			$uid = [Convert]::ToBase64String($Options.PublicKeyOptions.User.Id)
			$uname = $Options.PublicKeyOptions.User.Name
			
			
			###region ClientDataJSON/Hash
			
			#template for clientdata, as written in W3C documentation
			$samplejson='
			{"type":"webauthn.create",
			"challenge":"TZxCee-4fMYIDJz_PbvmdfW82WarB4vaevgJpBK_F2w",
			"origin":"https://site.tld",
			"crossOrigin":false
			}'
			$clientdata = ConvertFrom-Json -InputObject $samplejson
			
			$clientdata.origin= "https://" + $rpid
			
			
			#challenge as Base64url, https://www.w3.org/TR/webauthn-2/#dictionary-client-data
			$chlb64url= ConvertTo-Base64Url $Options.PublicKeyOptions.challenge
			
			
			$clientdata.challenge = $chlb64url
			$clientDataJSON = ConvertTo-Json -InputObject $clientdata -Compress
			
			
			#Create clientDataHash, in Base64, https://developers.yubico.com/libfido2/Manuals/fido2-cred.html
			$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
			$clientdatahashraw = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
			$clientdatahash = [Convert]::ToBase64String($clientdatahashraw)
			
			###endregion
			
			
			
			#initialize with base flags (PIN and create, rest if needed)
            $cli="-w $pin -M"

			#create with user Verification (UV)
			$uv = $Options.PublicKeyOptions.AuthenticatorSelection.UserVerificationRequirement
			if( $uv ) {
				$cli = $cli + " -v"
			}
			#create as resident/discoverable credential
			$rk = $Options.PublicKeyOptions.AuthenticatorSelection.RequireResidentKey
			if( $rk ) {
				$cli = $cli + " -r"
			}
			#create with hmac-secret
			$hmac = $Options.PublicKeyOptions.Extensions.HmacCreateSecret
			if( $hmac ) {
				$cli = $cli + " -h"
			}
			#credProtect
			$cp = $Options.PublicKeyOptions.Extensions.CredProtect.value__
			if( Is-Numeric($cp) ) {
				$cli = $cli + " -c " + $cp
			}
			
			#get eligible FIDO Devices, please only have one FIDO Device connected at a time
			$devicelist = (& "$PSScriptRoot\libfido2-ui.exe" -L).Split([Environment]::NewLine)
			
			foreach ($fidodevice in $devicelist) {
				$devicepath=($fidodevice -Split ": ")[0]
				#take first device that is not windows hello.
				if($devicepath -ne "windows://hello") {
					Break
				}
			}
			#add chosen device as final argument
			$cli = $cli + " $devicepath" 
			
			
			#prepare clientDataHash(base64), RPID, Username and user ID(base64) as Inputs for fido2-cred
			$input= $clientdatahash + "`n" + $rpid + "`n" + $uname + "`n" + $uid + "`n"
			
            # Keep the current output encoding in a variable
            $oldEncoding = [console]::OutputEncoding
            # Set the output encoding to use UTF8 without BOM
            [console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

            #modded for nfc and pin, pipe in inputs as UTF-8 to avoid writing unneeded files
            $cred = $input | & ".\fido2-cred2.exe" $cli.split()

            [console]::OutputEncoding = $oldEncoding

            # Controle : echec de fido2-cred2 (PIN incorrect, cle non touchee,
            # delai depasse, cle debranchee) -> sortie vide ou code non nul
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace("$cred")) {
                throw "fido2-cred2.exe a echoue (code $LASTEXITCODE). Causes probables : PIN incorrect (cle deja initialisee ?), cle non touchee a temps, ou cle debranchee. Sortie brute : $cred"
            }

			#construit un tableau a partir de la sortie et extrait authenticator data, signature et certificat d'attestation (x5c) pour batir manuellement l'attestation object
			$credarray=$cred -Split "`n"

            # Controle : la sortie doit contenir au moins 7 lignes exploitables
            if (@($credarray).Count -lt 7) {
                throw "Sortie de fido2-cred2.exe inattendue ($(@($credarray).Count) ligne(s)) : impossible d'extraire le credential. Sortie brute : $cred"
            }

			$authdata=$credarray[3]
			$sig=$credarray[5]
			$x5c=$credarray[6]
			$attobj = build-att-object $sig $authdata $x5c "es256"
			
			#recupere le credential ID en Base64URL a envoyer a Microsoft
			$credid=ConvertTo-Base64Url -FromBase64 $credarray[4]

            # Controle : jamais envoyer un credential vide a Graph (-> 400)
            if ([string]::IsNullOrWhiteSpace($credid) -or [string]::IsNullOrWhiteSpace($authdata)) {
                throw "Credential vide apres extraction : la creation sur la cle n'a pas abouti. Sortie brute de fido2-cred2 : $cred"
            }
			
			#sortie
			
			## format du credential, repris de la documentation Microsoft
			$samplejson2=@"
			{
			  "displayName": "Sample",
			  "publicKeyCredential": {
				"id": "pgI",
				"response": {
				  "clientDataJSON": "VGhpcy",
				  "attestationObject": "VGhpcy"
				}
			  }
			}
"@
			#prepare everything for sending to Microsoft
			$send = ConvertFrom-Json -InputObject $samplejson2
			$send.displayName=$DisplayName
			$send.publicKeyCredential.response.clientDataJSON=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
			$send.publicKeyCredential.response.attestationObject=$attobj
			$send.publicKeyCredential.id=$credid
			$sendjson=ConvertTo-Json -InputObject $send
			return $sendjson
        }
        catch {
            throw
        }
    }
}


function Show-NativeDialog {
    param (
        [ScriptBlock]$dialogAction
    )
    $dialogAction.Invoke()
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
}


function Show-ModalDialog {
    param (
        [System.Windows.Forms.Form]$dialog
    )
    $dialog.StartPosition = "CenterParent"
    $dialog.ShowDialog() | Out-Null
}

function Bring-MainWindowToForeground {
    if (-not ([System.Management.Automation.PSTypeName]'User32').Type) {
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public class User32 {
                [DllImport("user32.dll")]
                public static extern bool SetForegroundWindow(IntPtr hWnd);
            }
"@
    }

    $form.Activate()
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
}

# import des modules requis
Add-Type -AssemblyName System.Windows.Forms

# =====================================================================
#  Configuration generale
# =====================================================================
$script:ScriptVersion = '2.7.0-IFPEN'

# Repertoire des logs : par defaut sous le dossier du script.
# Cible production : zone reseau dediee avec ACL append-only, ex.
#   $script:LogDir = '\\SERVEUR\Partage\MFA-Enrollment-Logs'
$script:LogDir = Join-Path $PSScriptRoot 'Logs'


$script:LogHeader = 'Horodatage,Technicien,Poste,Collaborateur,NumeroSerie,PIN,ForcePINChange,Statut,MailSent'

# Rotation quotidienne : la date est integree au nom du fichier.
function Get-EnrollmentLogPath {
    Join-Path $script:LogDir ("enrollment_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd'))
}

# Ecriture d'une entree de log (succes, echec ou utilisateur ignore).
# Compatible ACL append-only : Add-Content uniquement, pas de lecture requise.
function Write-EnrollmentLog {
    param(
        [Parameter(Mandatory)] [string] $Upn,
        [string] $Serial          = '',
        [string] $Pin             = '',
        [bool]   $ForcedPinChange = $false,
        [Parameter(Mandatory)]
        [ValidateSet('Succes','Echec','Ignore')]
        [string] $Statut,
        [bool]   $MailSent        = $false,
        [string] $CredentialId    = '',
        [string] $Detail          = ''
    )

    if (-not (Test-Path $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }
    $logPath = Get-EnrollmentLogPath

    # En-tete si le fichier du jour n'existe pas encore (best effort :
    # sous ACL append-only stricte, [File]::Exists peut echouer -> ignore)
    try {
        if (-not [System.IO.File]::Exists($logPath)) {
            Add-Content -Path $logPath -Value $script:LogHeader -Encoding UTF8 -ErrorAction Stop
        }
    } catch { }

    $statutComplet = if ($Detail) { "$Statut ($Detail)" } else { $Statut }

    $fields = @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        "$env:USERDOMAIN\$env:USERNAME"
        $env:COMPUTERNAME
        $Upn
        $Serial
        $Pin
        $ForcedPinChange
        $statutComplet
        $MailSent
    )
    $line = ($fields | ForEach-Object { '"' + ("$_" -replace '"','""') + '"' }) -join ','

    try {
        Add-Content -Path $logPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Le log d'audit est obligatoire : on refuse de continuer sans trace.
        throw "Echec d'ecriture du log d'audit ($logPath) : $($_.Exception.Message)"
    }
}

# Retourne le nombre de passkeys FIDO2 deja enregistrees pour un UPN.
# Scope requis : UserAuthenticationMethod.ReadWrite.All (deja demande au Connect-MgGraph).
# Leve une exception si l'appel echoue (UPN introuvable, droits, reseau...).
function Get-ExistingPasskeyCount {
    param([Parameter(Mandatory)][string] $Upn)
    $uri = "https://graph.microsoft.com/v1.0/users/$Upn/authentication/fido2Methods"
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
    return @($resp.value).Count
}

# =====================================================================
#  Connexion Graph (reutilisable : recherche de groupe ET demarrage)
# =====================================================================
$script:GraphScopes = @(
    'UserAuthenticationMethod.ReadWrite.All',
    'Mail.Send',
    'GroupMember.Read.All',   # recherche de groupes + lecture des membres
    'User.Read.All'           # lecture de accountEnabled
)

# Se connecte a Graph uniquement si aucun contexte n'existe, si des scopes manquent
# ou si le tenant saisi a change depuis la derniere connexion.
$script:GraphTenant = $null
function Connect-GraphIfNeeded {
    param([Parameter(Mandatory)][string] $TenantId)
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $missing = if ($ctx) { @($script:GraphScopes | Where-Object { $ctx.Scopes -notcontains $_ }) } else { $script:GraphScopes }
    $tenantChanged = ($script:GraphTenant -and $script:GraphTenant -ne $TenantId)
    if (-not $ctx -or $missing.Count -gt 0 -or $tenantChanged) {
        Write-Host "Connexion a Microsoft Graph"
        Connect-MgGraph -Scopes $script:GraphScopes -TenantId $TenantId -NoWelcome
    }
    $script:GraphTenant = $TenantId
}

# Recherche de groupes Entra par nom (recherche "contient un mot" via $search)
# $script:LastGroupSearchTotal : nombre total de groupes correspondants (@odata.count)
function Search-EntraGroup {
    param([Parameter(Mandatory)][string] $Text)
    $safe = $Text.Replace('"', '')
    $search = [uri]::EscapeDataString("`"displayName:$safe`"")
    $uri = "https://graph.microsoft.com/v1.0/groups?`$search=$search" +
           "&`$select=id,displayName,description,mail,groupTypes,securityEnabled" +
           "&`$orderby=displayName&`$top=100&`$count=true"
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' }
    $script:LastGroupSearchTotal = $resp.'@odata.count'
    return @($resp.value)
}

# UPN des utilisateurs ACTIFS du groupe (membres transitifs, pagination geree)
function Get-EntraGroupActiveUserUpns {
    param([Parameter(Mandatory)][string] $GroupId)
    $upns = New-Object System.Collections.Generic.List[string]
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user" +
           "?`$select=userPrincipalName,accountEnabled&`$top=999"
    while ($uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($u in $resp.value) {
            if ($u.accountEnabled -eq $true -and $u.userPrincipalName) {
                $upns.Add([string]$u.userPrincipalName)
            }
        }
        $uri = $resp.'@odata.nextLink'
    }
    return @($upns | Sort-Object -Unique)
}

# Fenetre de recherche/selection de groupe. Retourne @{Id;DisplayName} ou $null.
function Show-GroupPicker {
    param([System.Windows.Forms.IWin32Window] $Owner)
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Rechercher un groupe Entra ID"
    $dlg.Size = New-Object System.Drawing.Size(620, 440)
    $dlg.StartPosition = "CenterParent"
    $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Point(15, 15)
    $txt.Width = 460
    $dlg.Controls.Add($txt)

    $btnSearch = New-Object System.Windows.Forms.Button
    $btnSearch.Text = "Rechercher"
    $btnSearch.Width = 100
    $btnSearch.Location = New-Object System.Drawing.Point(490, 13)
    $dlg.Controls.Add($btnSearch)
    $dlg.AcceptButton = $btnSearch   # Entree = rechercher

    $lv = New-Object System.Windows.Forms.ListView
    $lv.Location = New-Object System.Drawing.Point(15, 50)
    $lv.Size = New-Object System.Drawing.Size(575, 290)
    $lv.View = [System.Windows.Forms.View]::Details
    $lv.FullRowSelect = $true
    $lv.MultiSelect = $false
    $lv.HideSelection = $false
    [void]$lv.Columns.Add("Nom", 220)
    [void]$lv.Columns.Add("Type", 90)
    [void]$lv.Columns.Add("Description", 260)
    $dlg.Controls.Add($lv)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Location = New-Object System.Drawing.Point(15, 350)
    $lblStatus.Size = New-Object System.Drawing.Size(360, 40)
    $lblStatus.Text = "Saisissez au moins 2 caractères puis Rechercher."
    $dlg.Controls.Add($lblStatus)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = "Sélectionner"
    $btnOk.Width = 100
    $btnOk.Enabled = $false
    $btnOk.Location = New-Object System.Drawing.Point(380, 360)
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlg.Controls.Add($btnOk)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Annuler"
    $btnCancel.Width = 100
    $btnCancel.Location = New-Object System.Drawing.Point(490, 360)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.Controls.Add($btnCancel)
    $dlg.CancelButton = $btnCancel

    $btnSearch.Add_Click({
        $q = $txt.Text.Trim()
        if ($q.Length -lt 2) { $lblStatus.Text = "Saisissez au moins 2 caractères."; return }
        $lblStatus.Text = "Recherche en cours..."
        $dlg.Refresh()
        $lv.Items.Clear()
        $btnOk.Enabled = $false
        try {
            $groups = @(Search-EntraGroup -Text $q)
            foreach ($g in $groups) {
                $type = if ($g.groupTypes -contains 'Unified') { 'Microsoft 365' }
                        elseif ($g.securityEnabled) { 'Sécurité' }
                        else { 'Distribution' }
                $item = New-Object System.Windows.Forms.ListViewItem([string]$g.displayName)
                [void]$item.SubItems.Add($type)
                [void]$item.SubItems.Add([string]$g.description)
                $item.Tag = @{ Id = [string]$g.id; DisplayName = [string]$g.displayName }
                [void]$lv.Items.Add($item)
            }
            $lblStatus.Text = "$($groups.Count) groupe(s) trouvé(s)."
            if ($script:LastGroupSearchTotal -and $script:LastGroupSearchTotal -gt $groups.Count) {
                $lblStatus.Text = "$($groups.Count) premiers groupes affichés sur $($script:LastGroupSearchTotal) : affinez la recherche."
            }
        } catch {
            $lblStatus.Text = "Erreur : $($_.Exception.Message)"
        }
    })

    $lv.Add_SelectedIndexChanged({ $btnOk.Enabled = ($lv.SelectedItems.Count -eq 1) })
    $lv.Add_DoubleClick({
        if ($lv.SelectedItems.Count -eq 1) {
            $dlg.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $dlg.Close()
        }
    })

    $result = if ($Owner) { $dlg.ShowDialog($Owner) } else { $dlg.ShowDialog() }
    $selected = $null
    if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $lv.SelectedItems.Count -eq 1) {
        $selected = $lv.SelectedItems[0].Tag
    }
    $dlg.Dispose()
    return $selected
}

# =====================================================================
#  Tenant ID en registre
# =====================================================================
$regPath = "HKCU:\Software\Token2BulkFido"
$propertyName = "TenantId"
$defaultValue = "votretenant.onmicrosoft.com"   # <-- valeur par defaut a adapter

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
try {
    $null = Get-ItemProperty -Path $regPath -Name $propertyName -ErrorAction Stop
} catch {
    New-ItemProperty -Path $regPath -Name $propertyName -Value $defaultValue -PropertyType String -Force | Out-Null
}

# =====================================================================
#  Envoi du PIN temporaire par mail (delegue : depuis la boite du
#  compte connecte a Graph). Retourne $true si l'envoi a reussi.
# =====================================================================
function Send-PinMail {
    param(
        [Parameter(Mandatory)][string] $ToUpn,
        [Parameter(Mandatory)][string] $Pin,
        [Parameter(Mandatory)][string] $Serial
    )
    $subject = "Votre cle de securite FIDO2 - code PIN temporaire"

    $body = @"
Bonjour,

Votre clé de sécurité FIDO2 (numéro de série : $Serial) vient d'être préparée.

Votre code PIN temporaire est : $Pin

IMPORTANT : lors de votre première utilisation, il vous sera demandé de remplacer ce code temporaire par un code PIN personnel de votre choix.

Ne communiquez ce code à personne.

Cordialement,

Sécurité IFPEN
"@
    $payload = @{
        message = @{
            subject = $subject
            body = @{ contentType = "Text"; content = $body }
            toRecipients = @(@{ emailAddress = @{ address = $ToUpn } })
        }
        saveToSentItems = $true
    }
    # /me/sendMail : envoie depuis la boite du compte connecte
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $payload
}

# =====================================================================
#  Interface principale (francais)
# =====================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enrôlement des clés FIDO2"
$form.Size = New-Object System.Drawing.Size(520, 470)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false

# --- Tenant ID ---
$labelTenant = New-Object System.Windows.Forms.Label
$labelTenant.Text = "ID du tenant :"
$labelTenant.AutoSize = $true
$labelTenant.Location = New-Object System.Drawing.Point(20, 22)
$form.Controls.Add($labelTenant)

$textTenantId = New-Object System.Windows.Forms.TextBox
$textTenantId.Location = New-Object System.Drawing.Point(160, 20)
$textTenantId.Width = 320
$form.Controls.Add($textTenantId)

try {
    $tenantIdFromRegistry = (Get-ItemProperty -Path $regPath -Name "TenantId").TenantId
    if (-not [string]::IsNullOrWhiteSpace($tenantIdFromRegistry)) {
        $textTenantId.Text = $tenantIdFromRegistry
    }
} catch {
    Write-Host "Impossible de lire l'ID du tenant depuis le registre : $_"
}

# --- Source des utilisateurs : fichier CSV ou groupe Entra ID ---
$rbCsv = New-Object System.Windows.Forms.RadioButton
$rbCsv.Text = "Fichier CSV"
$rbCsv.AutoSize = $true
$rbCsv.Checked = $true
$rbCsv.Location = New-Object System.Drawing.Point(20, 55)
$form.Controls.Add($rbCsv)

$rbGroup = New-Object System.Windows.Forms.RadioButton
$rbGroup.Text = "Groupe Entra ID (utilisateurs actifs)"
$rbGroup.AutoSize = $true
$rbGroup.Location = New-Object System.Drawing.Point(160, 55)
$form.Controls.Add($rbGroup)

# --- Fichier CSV des utilisateurs ---
$btnSelectFile = New-Object System.Windows.Forms.Button
$btnSelectFile.Text = "Fichier CSV..."
$btnSelectFile.Width = 120
$btnSelectFile.Location = New-Object System.Drawing.Point(20, 85)
$form.Controls.Add($btnSelectFile)

$labelFilePath = New-Object System.Windows.Forms.Label
$labelFilePath.AutoSize = $true
$labelFilePath.MaximumSize = New-Object System.Drawing.Size(320, 0)
$labelFilePath.Location = New-Object System.Drawing.Point(160, 90)
$labelFilePath.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$labelFilePath.Text = "(aucun fichier sélectionné)"
$form.Controls.Add($labelFilePath)

# --- Groupe Entra ID ---
$btnSelectGroup = New-Object System.Windows.Forms.Button
$btnSelectGroup.Text = "Choisir un groupe..."
$btnSelectGroup.Width = 120
$btnSelectGroup.Enabled = $false
$btnSelectGroup.Location = New-Object System.Drawing.Point(20, 120)
$form.Controls.Add($btnSelectGroup)

$labelGroup = New-Object System.Windows.Forms.Label
$labelGroup.AutoSize = $true
$labelGroup.MaximumSize = New-Object System.Drawing.Size(320, 0)
$labelGroup.Location = New-Object System.Drawing.Point(160, 125)
$labelGroup.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$labelGroup.Text = "(aucun groupe sélectionné)"
$form.Controls.Add($labelGroup)

$script:SelectedGroup = $null

# Le groupe selectionne appartient au tenant courant : on l'oublie si le tenant change
$textTenantId.Add_TextChanged({
    if ($script:SelectedGroup) {
        $script:SelectedGroup = $null
        $labelGroup.Text = "(aucun groupe sélectionné)"
    }
})

$updateSource = {
    $btnSelectFile.Enabled  = $rbCsv.Checked
    $btnSelectGroup.Enabled = $rbGroup.Checked
}
$rbCsv.Add_CheckedChanged($updateSource)
$rbGroup.Add_CheckedChanged($updateSource)

$btnSelectFile.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Fichiers CSV (*.csv)|*.csv|Tous les fichiers (*.*)|*.*"
    $openFileDialog.Title = "Sélectionner le fichier CSV des utilisateurs (colonne UPN)"
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $labelFilePath.Text = $openFileDialog.FileName
    }
})

$btnSelectGroup.Add_Click({
    if (-not $textTenantId.Text) {
        [System.Windows.Forms.MessageBox]::Show("Veuillez saisir l'ID du tenant.", "Erreur")
        return
    }
    try {
        Connect-GraphIfNeeded -TenantId $textTenantId.Text
        $g = Show-GroupPicker -Owner $form
        if ($g) {
            $script:SelectedGroup = $g
            $labelGroup.Text = "$($g.DisplayName)`n($($g.Id))"
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Connexion/recherche impossible :`n$($_.Exception.Message)", "Erreur")
    }
})

# --- Options de securite : IMPOSEES (cochees et verrouillees) ---
$chkSetRandomPin = New-Object System.Windows.Forms.CheckBox
$chkSetRandomPin.Text = "PIN aléatoire (obligatoire)"
$chkSetRandomPin.AutoSize = $true
$chkSetRandomPin.Location = New-Object System.Drawing.Point(20, 165)
$chkSetRandomPin.Checked = $true
$chkSetRandomPin.Enabled = $false
$form.Controls.Add($chkSetRandomPin)

$chkForcePinChange = New-Object System.Windows.Forms.CheckBox
$chkForcePinChange.Text = "Changement de PIN obligatoire à la première utilisation"
$chkForcePinChange.AutoSize = $true
$chkForcePinChange.Location = New-Object System.Drawing.Point(20, 130)
$chkForcePinChange.Checked = $true
$chkForcePinChange.Enabled = $false
$form.Controls.Add($chkForcePinChange)

# --- Repertoire des logs ---
$btnSetLogDir = New-Object System.Windows.Forms.Button
$btnSetLogDir.Text = "Paramétrage logs..."
$btnSetLogDir.Width = 120
$btnSetLogDir.Location = New-Object System.Drawing.Point(20, 165)
$form.Controls.Add($btnSetLogDir)

$labelLogDir = New-Object System.Windows.Forms.Label
$labelLogDir.AutoSize = $true
$labelLogDir.MaximumSize = New-Object System.Drawing.Size(320, 0)
$labelLogDir.Location = New-Object System.Drawing.Point(160, 170)
$labelLogDir.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$labelLogDir.Text = $script:LogDir
$form.Controls.Add($labelLogDir)

$btnSetLogDir.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Choisir le répertoire des fichiers de log"
    if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        # $script: obligatoire : une affectation simple resterait locale au handler
        $script:LogDir = $folderDialog.SelectedPath
        $labelLogDir.Text = $script:LogDir
    }
})

# --- Instructions ---
$lblInstruction = New-Object System.Windows.Forms.Label
$lblInstruction.Text = "Branchez la clé du premier utilisateur avant de commencer`n(ou utilisez le NFC pour limiter les manipulations)"
$lblInstruction.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
$lblInstruction.AutoSize = $true
$lblInstruction.Location = New-Object System.Drawing.Point(20, 215)
$form.Controls.Add($lblInstruction)

# --- Bouton principal ---
$btnProceed = New-Object System.Windows.Forms.Button
$btnProceed.Text = "Démarrer"
$btnProceed.Width = 220
$btnProceed.Height = 40
$btnProceed.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)
$btnProceed.Location = New-Object System.Drawing.Point(20, 270)
$form.Controls.Add($btnProceed)

$btnProceed.Add_Click({
    Write-Host "Verification des donnees saisies"

    try {
        $tenantId = $textTenantId.Text
        $filePath = $labelFilePath.Text

        if (-not $tenantId) {
            [System.Windows.Forms.MessageBox]::Show("Veuillez saisir l'ID du tenant.", "Erreur")
            $form.Visible = $true
            return
        }

        if ($rbCsv.Checked -and (-not $filePath -or -not (Test-Path $filePath))) {
            [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner un fichier CSV valide.", "Erreur")
            $form.Visible = $true
            return
        }

        if ($rbGroup.Checked -and -not $script:SelectedGroup) {
            [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner un groupe Entra ID.", "Erreur")
            $form.Visible = $true
            return
        }

        Set-ItemProperty -Path $regPath -Name "TenantId" -Value $tenantId -Force
        Connect-GraphIfNeeded -TenantId $tenantId

        if ($rbGroup.Checked) {
            Write-Host "Lecture des membres actifs du groupe $($script:SelectedGroup.DisplayName)..."
            $upns = @(Get-EntraGroupActiveUserUpns -GroupId $script:SelectedGroup.Id)
            if ($upns.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("Aucun utilisateur actif dans ce groupe.", "Information")
                $form.Visible = $true
                return
            }
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "$($upns.Count) utilisateur(s) actif(s) dans le groupe '$($script:SelectedGroup.DisplayName)'.`n`nDémarrer l'enrôlement ?",
                "Confirmation",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
                $form.Visible = $true
                return
            }
        } else {
            $upns = @(Import-Csv $filePath | Select-Object -ExpandProperty UPN)
        }

        $totalUsers = $upns.Count
        $currentIndex = 0
        $script:StopRequested = $false   # arret volontaire par l'operateur

        foreach ($upn in $upns) {
            if (-not $upn) { continue }

            # Arret demande : on sort proprement de la boucle (aucun enrolement
            # n'est en cours a ce point, la sortie est sans risque).
            if ($script:StopRequested) {
                Write-Host "Arret demande par l'operateur. Utilisateurs restants non traites."
                break
            }

            $currentIndex++

            # --- Pre-controle : le compte a-t-il deja une passkey ? ---
            # Evite toute manipulation (popup, lecture de serie) pour les
            # comptes deja enroles ou introuvables : ignore et journalise.
            try {
                $existingCount = Get-ExistingPasskeyCount -Upn $upn
                if ($existingCount -gt 0) {
                    Write-Host "$upn : $existingCount passkey(s) deja enregistree(s), utilisateur ignore."
                    Write-EnrollmentLog -Upn $upn -Statut 'Ignore' -Detail "Passkey deja existante ($existingCount)"
                    continue
                }
            } catch {
                Write-Host "$upn : verification impossible ($($_.Exception.Message)), utilisateur ignore."
                Write-EnrollmentLog -Upn $upn -Statut 'Ignore' -Detail "Verification impossible : $($_.Exception.Message)"
                continue
            }

            # --- Sequence de changement de cle (garantit un serie unique) ---
            # Etape 1 : exiger le retrait de TOUTE cle avant de continuer.
            # Etape 2 : exiger l'insertion d'UNE seule cle, puis lire le serie
            # avec l'expression d'origine (qui renvoie le serie complet).
            # Une cle est "presente" si read_serial_t2 renvoie autre chose que
            # vide/None ; "plusieurs cles" si la sortie contient une virgule.
            $serialOutput = $null
            $skipUser = $false

            # Etape 1 : attendre poste a vide
            while ($true) {
                $chk = (& "$PSScriptRoot\read_serial_t2.exe" 2>$null)
                $chk = if ($null -ne $chk) { ("$chk").Trim() } else { '' }
                if ([string]::IsNullOrWhiteSpace($chk) -or $chk -eq 'None') { break }  # poste a vide
                $res = [System.Windows.Forms.MessageBox]::Show(
                    "Prochain collaborateur : $upn`n`n" +
                    "ETAPE 1 - Retirez la cle actuellement branchee.`n`n" +
                    "Cliquez sur OK une fois la cle retiree, ou Annuler pour arreter.",
                    "Retirez la cle",
                    [System.Windows.Forms.MessageBoxButtons]::OKCancel,
                    [System.Windows.Forms.MessageBoxIcon]::Information)
                if ($res -eq [System.Windows.Forms.DialogResult]::Cancel) {
                    $script:StopRequested = $true
                    $skipUser = $true
                    break
                }
            }
            if ($skipUser) {
                Write-EnrollmentLog -Upn $upn -Statut 'Ignore' -Detail "Non enrole - arret demande avant lecture"
                continue
            }

            # Etape 2 : attendre l'insertion d'UNE seule cle et lire le serie
            while ($true) {
                $res = [System.Windows.Forms.MessageBox]::Show(
                    "Collaborateur : $upn`n`n" +
                    "ETAPE 2 - Branchez la cle de ce collaborateur.`n`n" +
                    "Cliquez sur OK une fois la cle branchee, ou Annuler pour ignorer cet utilisateur.",
                    "Branchez la cle",
                    [System.Windows.Forms.MessageBoxButtons]::OKCancel,
                    [System.Windows.Forms.MessageBoxIcon]::Information)
                if ($res -eq [System.Windows.Forms.DialogResult]::Cancel) {
                    Write-Host "$upn : insertion annulee, utilisateur ignore."
                    Write-EnrollmentLog -Upn $upn -Statut 'Ignore' -Detail "Cle non branchee (annule par operateur)"
                    $skipUser = $true
                    break
                }
                # Lecture avec l'expression d'origine (serie complet, non decoupe)
                $raw = (& "$PSScriptRoot\read_serial_t2.exe").Trim()
                if ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq 'None') {
                    [System.Windows.Forms.MessageBox]::Show("Aucune cle detectee. Branchez la cle avant de cliquer sur OK.", "Aucune cle")
                    continue
                }
                if ($raw -match ',') {
                    [System.Windows.Forms.MessageBox]::Show("Plusieurs cles detectees ($raw).`nNe laissez qu'UNE seule cle branchee, puis reessayez.", "Plusieurs cles")
                    continue
                }
                # exactement une cle : serie complet
                $serialOutput = $raw
                break
            }
            if ($skipUser -or [string]::IsNullOrWhiteSpace($serialOutput)) { continue }


            # Detection du numero de device pour fido2-manage (evite -device 1 en dur).
            # fido2-manage -list appelle aussi .\libfido2-ui.exe -> Push-Location.
            $script:DeviceNumber = 1
            try {
                Push-Location $PSScriptRoot
                try {
                    $manageList = (& "$PSScriptRoot\fido2-manage.exe" -list 2>&1) | Out-String
                } finally { Pop-Location }
                # Recupere le 1er numero de device liste (format "1: <path>" ou "device 1")
                # Format observe : "Device [1]: TOKEN2 FIDO2 Security Key(...)"
                $m = [regex]::Match($manageList, '(?im)device\s*\[?\s*(\d+)\s*\]?\s*:')
                if ($m.Success) { $script:DeviceNumber = [int]$m.Groups[1].Value }
                Write-Host "Device fido2-manage retenu : $script:DeviceNumber"
            } catch {
                Write-Host "Detection du device impossible, valeur par defaut 1 utilisee. ($($_.Exception.Message))"
            }

            # PIN aleatoire : systematique (option verrouillee)
            $randomPin = New-RandomPin

            # Fenetre intermediaire pour l'operateur
            $serialPopup = New-Object System.Windows.Forms.Form
            $serialPopup.Text = "Enrôlement de la clé pour $upn"
            $serialPopup.Size = New-Object System.Drawing.Size(440, 260)
            $serialPopup.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

            # NOTE etape ulterieure (envoi du PIN par mail) : cet affichage du
            # PIN sera supprime pour retirer toute visibilite cote technicien.
            $serialLabel = New-Object System.Windows.Forms.Label
            $serialLabel.Text = "Numéro de série : $serialOutput`nUtilisateur : $upn"
            $serialLabel.AutoSize = $true
            $serialPopup.Controls.Add($serialLabel)

            $infoLabel = New-Object System.Windows.Forms.Label
            $infoLabel.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)
            $infoLabel.Text = "Si la clé clignote, touchez la zone métallique."
            $infoLabel.Location = New-Object System.Drawing.Point(20, 60)
            $infoLabel.Size = New-Object System.Drawing.Size(380, 30)
            $serialPopup.Controls.Add($infoLabel)

            $infoLabel2 = New-Object System.Windows.Forms.Label
            $infoLabel2.Text = "(Fermez cette fenêtre pour ignorer cet utilisateur)"
            $infoLabel2.Location = New-Object System.Drawing.Point(20, 150)
            $infoLabel2.Size = New-Object System.Drawing.Size(380, 20)
            $serialPopup.Controls.Add($infoLabel2)

            $btnAddKey = New-Object System.Windows.Forms.Button
            $btnAddKey.Text = "Initialiser la clé"
            $btnAddKey.Width = 120
            $btnAddKey.Location = New-Object System.Drawing.Point(20, 105)
            $serialPopup.Controls.Add($btnAddKey)

            # Bouton d'arret : stoppe la campagne apres cet utilisateur.
            $btnStop = New-Object System.Windows.Forms.Button
            $btnStop.Text = "Arrêter la campagne"
            $btnStop.Width = 150
            $btnStop.Location = New-Object System.Drawing.Point(160, 105)
            $serialPopup.Controls.Add($btnStop)

            $btnStop.Add_Click({
                $confirm = [System.Windows.Forms.MessageBox]::Show(
                    "Arrêter l'enrôlement maintenant ?`n`nL'utilisateur en cours ne sera pas enrôlé et les utilisateurs restants seront ignorés.",
                    "Confirmer l'arrêt",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning)
                if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
                    $script:StopRequested = $true
                    $serialPopup.Close()
                }
            })

            $script:KeyProcessed = $false

            $btnAddKey.Add_Click({
                Write-Host "Traitement de $upn (serie : $serialOutput)"
                $script:KeyProcessed = $true

                try {
                    Write-Host "Definition du PIN via fido2-manage.exe..."
                    # fido2-manage.exe appelle en interne .\libfido2-ui.exe (chemin
                    # relatif au repertoire courant) : on se place dans $PSScriptRoot
                    # le temps de l'appel pour qu'il retrouve son sous-outil.
                    Push-Location $PSScriptRoot
                    try {
                        $setPinOutput = (& "$PSScriptRoot\fido2-manage.exe" -setPIN -pin $randomPin -device $script:DeviceNumber 2>&1) | Out-String
                    } finally { Pop-Location }
                    if ($LASTEXITCODE -ne 0 -or $setPinOutput -match 'FIDO_ERR|error|failed') {
                        throw "Echec de la definition du PIN (code $LASTEXITCODE). La cle possede probablement deja un PIN (cle non vierge : reinitialisez-la avant reutilisation). Detail : $($setPinOutput.Trim())"
                    }

                    Write-Host "Enregistrement de la passkey pour $upn..."
                    $graphResult = Get-PasskeyRegistrationOptions -UserId $upn |
                        CTAP-Create-Custom-Passkey -DisplayName $serialOutput -pin $randomPin |
                        Graph-Register-Custom-Passkey -UserId $upn
                    $credentialId = if ($graphResult) { "$($graphResult.Id)" } else { '' }

                    Write-Host "Passkey enregistree pour $upn."

                    $forcedPin = $false
                    if ($chkForcePinChange.Checked) {
                        Write-Host "Activation du changement de PIN obligatoire..."
                        Push-Location $PSScriptRoot
                        try {
                            $forceOutput = (& "$PSScriptRoot\fido2-manage.exe" -forcePINchange -pin $randomPin -device $script:DeviceNumber 2>&1) | Out-String
                        } finally { Pop-Location }
                        if ($LASTEXITCODE -ne 0 -or $forceOutput -match 'FIDO_ERR|error|failed') {
                            throw "Echec de l'activation du changement de PIN obligatoire (code $LASTEXITCODE). Detail : $($forceOutput.Trim())"
                        }
                        $forcedPin = $true
                    }

                    # Envoi du PIN temporaire par mail au collaborateur
                    $mailSent = $false
                    try {
                        Send-PinMail -ToUpn $upn -Pin $randomPin -Serial $serialOutput
                        $mailSent = $true
                        Write-Host "Mail envoye a $upn."
                    } catch {
                        $mailErr = $_.Exception.Message
                        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $mailErr = "$mailErr | $($_.ErrorDetails.Message)" }
                        Write-Host "Echec envoi mail a $upn : $mailErr"
                    }

                    # Journalisation du succes. PIN NON stocke (transmis par mail,
                    # ephemere + Force PIN Change) : seul MailSent est trace.
                    Write-EnrollmentLog -Upn $upn -Serial $serialOutput -Pin '' `
                        -ForcedPinChange $forcedPin -Statut 'Succes' `
                        -MailSent $mailSent -CredentialId $credentialId
                    Write-Host "Resultat journalise pour $upn."

                    if ($currentIndex -lt $totalUsers) {
                        Write-Host "Utilisateur suivant..."
                    } else {
                        Write-Host "Tous les utilisateurs ont ete traites."
                    }

                } catch {
                    $errMsg = $_.Exception.Message
                    # Le corps de la reponse Graph contient le detail reel de
                    # l'erreur (code + raison), sinon masque par le message generique
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        $errMsg = "$errMsg | Detail Graph : $($_.ErrorDetails.Message)"
                    }
                    Write-Host "Erreur pendant l'enrolement : $errMsg"
                    Write-EnrollmentLog -Upn $upn -Serial $serialOutput -Pin '' `
                        -Statut 'Echec' -Detail $errMsg
                    [System.Windows.Forms.MessageBox]::Show("Une erreur est survenue pendant l'enrôlement :`n$errMsg", "Erreur")
                } finally {
                    $serialPopup.Close()
                }
            })

            $serialPopup.ShowDialog()

            # Fenetre fermee sans clic sur "Initialiser la clé" -> utilisateur ignore.
            # On distingue un arret volontaire d'un simple abandon d'utilisateur.
            if (-not $script:KeyProcessed) {
                if ($script:StopRequested) {
                    Write-Host "Arret : $upn non enrole (campagne stoppee)."
                    Write-EnrollmentLog -Upn $upn -Serial $serialOutput -Statut 'Ignore' -Detail "Non enrole - campagne arretee par l'operateur"
                } else {
                    Write-Host "Fenetre fermee : $upn ignore par l'operateur."
                    Write-EnrollmentLog -Upn $upn -Serial $serialOutput -Statut 'Ignore' -Detail "Ignore par l'operateur"
                }
            }
        }

        if ($script:StopRequested) {
            [System.Windows.Forms.MessageBox]::Show("Enrôlement arrêté par l'opérateur. Les utilisateurs restants n'ont pas été traités.", "Arrêté")
        } else {
            [System.Windows.Forms.MessageBox]::Show("Enrôlement terminé.", "Succes")
        }
        $form.Visible = $true
    } catch {
        Write-Host "Une erreur est survenue : $($_)"
        [System.Windows.Forms.MessageBox]::Show("Une erreur est survenue : $($_)", "Erreur")
        $form.Visible = $true
    }
})

$form.ShowDialog()

$form.add_Activated({
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
})
