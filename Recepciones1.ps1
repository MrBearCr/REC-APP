# ================= SISTEMA DE ACTUALIZACIÓN AUTOMÁTICA MEJORADO =================
$currentVersion = "1.0.2"  # ¡ACTUALIZAR EN CADA RELEASE!

# Configuración
$updateConfig = @{
    VersionUrl = "https://tu-servidor.com/RecepcionesApp/version.txt"
    ReleaseNotesUrl = "https://tu-servidor.com/RecepcionesApp/release_notes.txt"
    UpdateExeUrl = "https://tu-servidor.com/RecepcionesApp/Recepciones1.exe"
    LocalExePath = "$PSScriptRoot\Recepciones1.exe"
    TempUpdatePath = "$env:TEMP\Recepciones1_new_$([System.Guid]::NewGuid().ToString('N')).exe"
    LogPath = "$PSScriptRoot\update_log.txt"
    MaxRetries = 3
    RetryDelay = 5  # segundos
}

function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $updateConfig.LogPath -Value "$timestamp `t $message"
}

function Test-FileLock {
    param([string]$path)
    try {
        [IO.File]::OpenWrite($path).Close()
        return $false
    } catch {
        return $true
    }
}

function Invoke-SafeWebRequest {
    param($Url, $OutFile, [int]$RetryCount = 0)
    
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
        return $true
    } catch {
        if ($RetryCount -lt $updateConfig.MaxRetries) {
            Write-Log "Reintentando descarga ($($RetryCount+1)/$($updateConfig.MaxRetries))..."
            Start-Sleep -Seconds $updateConfig.RetryDelay
            return Invoke-SafeWebRequest -Url $Url -OutFile $OutFile -RetryCount ($RetryCount + 1)
        }
        throw "Error después de $($updateConfig.MaxRetries) intentos: $_"
    }
}

# Iniciar log
Write-Log "=== Inicio verificación de actualizaciones ==="
Write-Log "Versión actual: $currentVersion"

try {
    # Obtener versión remota
    $remoteVersion = (Invoke-SafeWebRequest -Url $updateConfig.VersionUrl -OutFile "$env:TEMP\version_temp.txt" | Get-Content) -replace '\s'
    
    Write-Log "Versión remota: $remoteVersion"
    
    if ([System.Version]$remoteVersion -gt [System.Version]$currentVersion) {
        Write-Log "Nueva versión disponible: $remoteVersion"
        
        # Descargar nueva versión
        Invoke-SafeWebRequest -Url $updateConfig.UpdateExeUrl -OutFile $updateConfig.TempUpdatePath
        Write-Log "Actualización descargada en: $($updateConfig.TempUpdatePath)"
        
        # Verificar integridad del archivo
        $fileSize = (Get-Item $updateConfig.TempUpdatePath).Length
        if ($fileSize -lt 100KB) {
            throw "Archivo descargado demasiado pequeño ($fileSize bytes). Posible error de descarga."
        }
        Write-Log "Tamaño del archivo verificado: $($fileSize/1MB) MB"

        # Obtener notas de versión
        $notes = Invoke-SafeWebRequest -Url $updateConfig.ReleaseNotesUrl -OutFile "$env:TEMP\release_notes_temp.txt" | Get-Content
        
        # Mostrar notificación no bloqueante
        $notifyScript = {
            param($notes, $version)
            Add-Type -AssemblyName PresentationFramework
            [System.Windows.MessageBox]::Show(
                "Nueva versión $version disponible. Se actualizará al reiniciar.`n`n$notes",
                "Actualización Disponible",
                'OK',
                'Information'
            )
        }
        Start-Job -ScriptBlock $notifyScript -ArgumentList $notes, $remoteVersion | Out-Null

        # Preparar script auxiliar mejorado
        $updaterScript = @"
# Reiniciar como administrador si es necesario
param([bool]\$IsAdmin = $([bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))

function Wait-FileUnlock {
    param([string]\$path, [int]\$maxSeconds = 30)
    \$start = Get-Date
    while ((Test-Path \$path) -and (Test-FileLock \$path) -and ((Get-Date) - \$start).TotalSeconds -lt \$maxSeconds) {
        Start-Sleep -Seconds 2
    }
}

Write-Host "Iniciando proceso de actualización..."
Start-Sleep -Seconds 3  # Esperar a que la instancia anterior se cierre

try {
    # Esperar a que el archivo se libere
    Wait-FileUnlock -path '$($updateConfig.LocalExePath)'
    
    if (Test-Path '$($updateConfig.LocalExePath)') {
        Remove-Item -Path '$($updateConfig.LocalExePath)' -Force -ErrorAction Stop
        Write-Host "Versión anterior eliminada"
    }
    
    Move-Item -Path '$($updateConfig.TempUpdatePath)' -Destination '$($updateConfig.LocalExePath)' -Force
    Write-Host "Nueva versión instalada"
    
    # Ejecutar como administrador si es necesario
    if (-not \$IsAdmin) {
        Start-Process -FilePath '$($updateConfig.LocalExePath)' -Verb RunAs
    } else {
        Start-Process -FilePath '$($updateConfig.LocalExePath)'
    }
    
    Write-Host "Nueva instancia iniciada"
    exit 0
} catch {
    Write-Host "Error en actualización: \$_"
    [System.Windows.MessageBox]::Show(
        "Error durante la actualización: \$_`nPor favor actualice manualmente.",
        "Error de Actualización",
        'OK',
        'Error'
    )
    exit 1
}
"@
        $updaterPath = "$env:TEMP\update_helper_$([System.Guid]::NewGuid().ToString('N')).ps1"
        $updaterScript | Out-File -FilePath $updaterPath -Encoding UTF8
        Write-Log "Script auxiliar creado en $updaterPath"

        # Iniciar proceso de actualización
        $psArgs = @{
            FilePath = "powershell.exe"
            ArgumentList = "-ExecutionPolicy Bypass -File `"$updaterPath`""
            Wait = $false
        }
        Start-Process @psArgs
        
        Write-Log "Actualización iniciada. Cerrando aplicación..."
        exit
    } else {
        Write-Log "No hay actualizaciones disponibles"
    }
}
catch {
    $errMsg = "Error en sistema de actualización: $_"
    Write-Host $errMsg
    Write-Log "ERROR: $errMsg"
    # Continuar con la ejecución normal
}

# ================= FIN DEL SISTEMA DE ACTUALIZACIÓN =================


# --- Configuración de licencia (segura) ---
$licPath = "$env:APPDATA\BDConnector\license.txt"
$lastCheckPath = "$env:APPDATA\BDConnector\lastcheck.txt"
$salt = "bdc0nn3c70R_S3cur1ty_S4lt_v2"  # Secreto para prevenir ataques de diccionario
$scriptVersion = "1.0.1"



# Función para generar hash seguro
function Get-SecureHash {
    param([string]$Data)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $saltedData = $Data + $salt
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($saltedData)
    $hashBytes = $sha256.ComputeHash($bytes)
    return [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLower()
}

# Asegurar directorio
if (-not (Test-Path "$env:APPDATA\BDConnector")) {
    New-Item -Path "$env:APPDATA\BDConnector" -ItemType Directory -Force | Out-Null
}


# Función para obtener la tabla de licencias
function Get-LicenseTable {
    try {
        $csvUrl = "https://docs.google.com/spreadsheets/d/e/2PACX-1vTdAdOg6pI7tOF-9UdFDzw0P5aSpNRc-jGIYHwOHmXb7qqOtag9QTYAi4JU0U2VoIZLd_TjvK_7cxX9/pub?output=csv"
        $resp = Invoke-WebRequest -Uri $csvUrl -UseBasicParsing -ErrorAction Stop
        return $resp.Content | ConvertFrom-Csv
    } catch {
        Write-Error "No se pudo descargar la hoja de licencias: $_"
        return @()
    }
}

function Get-LicenseInfo {
    param([string]$key)
    $table = Get-LicenseTable
    return $table | Where-Object { $_.LicenseKey -eq $key }
}

function Validate-LicenseKey {
    param([string]$key)
    $row = Get-LicenseInfo -key $key
    if (-not $row) { 
        return @{ Status = 'Invalid' } 
    }
    
    $exp = [DateTime]::ParseExact($row.ExpirationDate, 'yyyy-MM-dd', $null)
    $licenseVersion = [version]$row.Version
    
    # Verificar expiración
    if ([DateTime]::Now -gt $exp) {
        return @{ Status = 'Expired'; Expiration = $exp }
    }
    # Verificar versión
    if ([version]$scriptVersion -lt $licenseVersion) {
        return @{ Status = 'VersionMismatch'; RequiredVersion = $licenseVersion }
    }
    
    return @{
        Status = 'Valid'
        Key = $key
        Expiration = $exp
        Version = $licenseVersion
    }
}

# Guardar licencia con verificación de integridad
function Save-LicenseLocal {
    param([string]$key, [DateTime]$exp, [version]$version)
    $expDateStr = $exp.ToString('yyyy-MM-dd')
    $versionStr = $version.ToString()
    $rawData = "${key}|${expDateStr}|${versionStr}"
    $hash = Get-SecureHash -Data $rawData
    
    $obj = @{
        LicenseKey = $key
        ExpirationDate = $expDateStr
        Version = $versionStr
        IntegrityHash = $hash
    }
    $obj | ConvertTo-Json | Out-File -FilePath $licPath -Encoding UTF8 -Force
}

# Cargar licencia con verificación de integridad
function Load-LicenseLocal {
    if (-not (Test-Path $licPath)) { return $null }
    try {
        $obj = Get-Content $licPath -Raw | ConvertFrom-Json
        
        # Verificar nueva estructura con versión
        if (-not $obj.LicenseKey -or -not $obj.ExpirationDate -or `
            -not $obj.IntegrityHash -or -not $obj.Version) {
            return $null
        }
        
        # Calcular hash incluyendo versión
        $rawData = "$($obj.LicenseKey)|$($obj.ExpirationDate)|$($obj.Version)"
        $computedHash = Get-SecureHash -Data $rawData
        
        if ($obj.IntegrityHash -ne $computedHash) {
            Write-Warning "Detección de manipulación en archivo de licencia"
            return $null
        }
        
        return @{
            LicenseKey = $obj.LicenseKey
            ExpirationDate = $obj.ExpirationDate
            Version = $obj.Version
        }
    } catch { 
        return $null 
    }
}

# Función para obtener fecha de última verificación
function Get-LastCheckDate {
    if (Test-Path $lastCheckPath) {
        return [DateTime]::Parse((Get-Content $lastCheckPath))
    }
    return [DateTime]::MinValue
}

# Función para guardar fecha de verificación
function Set-LastCheckDate {
    [DateTime]::Now.ToString("o") | Out-File $lastCheckPath -Encoding UTF8
}

# Función para verificar si necesita comprobación
function Needs-LicenseCheck {
    $lastCheck = Get-LastCheckDate
    return ([DateTime]::Now - $lastCheck).TotalDays -gt 7
}

# Validación de licencia con caché
function Validate-LicenseWithCache {
    # Si no necesita verificación, usar caché local con verificación de hash
    if (-not (Needs-LicenseCheck)) {
        $local = Load-LicenseLocal
        if (-not $local) { return $false }
        $exp = [DateTime]::ParseExact($local.ExpirationDate, 'yyyy-MM-dd', $null)
        return ([DateTime]::Now -le $exp)
    }
    
    # Verificación en línea (con protección anti-manipulación)
    try {
        $local = Load-LicenseLocal
        if (-not $local) { return $false }
        
        $onlineInfo = Get-LicenseInfo -key $local.LicenseKey
        if (-not $onlineInfo) { return $false }

        $onlineVersion = [version]$onlineInfo.Version
        if ([version]$scriptVersion -lt $onlineVersion) {
            return $false
        }
        
        $onlineExp = [DateTime]::ParseExact($onlineInfo.ExpirationDate, 'yyyy-MM-dd', $null)
        $localExp = [DateTime]::ParseExact($local.ExpirationDate, 'yyyy-MM-dd', $null)
        
        # Detectar discrepancia que indique manipulación
        if ($onlineExp -ne $localExp) {
            # Guardar nueva versión validada con hash
            Save-LicenseLocal -key $local.LicenseKey -exp $onlineExp
            Write-Host "Licencia actualizada desde servidor" -ForegroundColor Yellow
        }
        
        Set-LastCheckDate
        return ([DateTime]::Now -le $onlineExp)
    }
    catch {
        $local = Load-LicenseLocal
        if (-not $local) { return $false }
        $exp = [DateTime]::ParseExact($local.ExpirationDate, 'yyyy-MM-dd', $null)
        return ([DateTime]::Now -le $exp)
    }
}

function Show-LicenseForm {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    Add-Type -AssemblyName System.Drawing | Out-Null
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Activación de Licencia"
    $form.Size = New-Object System.Drawing.Size(350,180)
    $form.StartPosition = "CenterScreen"
    
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Ingrese su clave de licencia:"
    $lbl.Location = New-Object System.Drawing.Point(10,20)
    $lbl.Size = New-Object System.Drawing.Size(320,20)
    
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Point(10,50)
    $txt.Size = New-Object System.Drawing.Size(320,23)
    
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "Activar"
    $btn.Location = New-Object System.Drawing.Point(120,90)
    $btn.Add_Click({
        $result = Validate-LicenseKey -key $txt.Text
        
        if ($result.Status -eq 'Valid') {
            Save-LicenseLocal -key $result.Key -exp $result.Expiration -version $result.Version
            $form.Tag = "OK"
            $form.Close()
        } 
        else {
            $errorMsg = switch ($result.Status) {
                'Invalid'   { "Licencia inválida." }
                'Expired'   { "Licencia expirada el $($result.Expiration.ToString('d'))." }
                'VersionMismatch' { 
                    "HAY UNA NUEVA VERSIÓN DISPONIBLE ($($result.RequiredVersion))`n" +
                    "Contacte con el proveedor para actualizar su software."
                }
                default     { "Error desconocido con la licencia." }
            }

            # Determinar el icono a mostrar
            if ($result.Status -eq 'VersionMismatch') {
                $icon = [System.Windows.Forms.MessageBoxIcon]::Information
            } else {
                $icon = [System.Windows.Forms.MessageBoxIcon]::Error
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                $errorMsg, 
                "Información de Licencia", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                $icon
            )
        }
    })

    $form.Controls.AddRange(@($lbl, $txt, $btn))
    $result = $form.ShowDialog()
    return $form.Tag -eq "OK"
}

# --- Verificar administrador ---
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    return ([Security.Principal.WindowsPrincipal]::new($currentUser)).IsInRole($adminRole)
}

# --- Validación de licencia ---
if (-not (Validate-LicenseWithCache)) {
    if (-not (Show-LicenseForm)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Debe activar una licencia válida para continuar.",
            "Licencia requerida",
            'OK',
            'Warning'
        )
        exit
    }
    # Validar nuevamente después de la activación
    if (-not (Validate-LicenseWithCache)) {
        [System.Windows.Forms.MessageBox]::Show(
            "La licencia activada no es válida o está expirada.",
            "Error de licencia",
            'OK',
            'Error'
        )
        exit
    }
}

# Cargar licencia y calcular días restantes
$local = Load-LicenseLocal
$expDate = [DateTime]::ParseExact($local.ExpirationDate, 'yyyy-MM-dd', $null)
$daysLeft = [math]::Max(0, ($expDate - [DateTime]::UtcNow.Date).Days)

# Relanzar como administrador
if (-not (Test-Admin)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Importar módulos necesarios
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

# Configuración persistente
$configPath = "$env:APPDATA\BDConnectorProfiles.xml"

# Función para cargar perfiles guardados
function Load-Profiles {
    if (Test-Path $configPath) {
        try {
            return Import-Clixml -Path $configPath
        }
        catch {
            Write-Host "Error cargando perfiles: $_" -ForegroundColor Red
            return @()
        }
    }
    return @()
}



# Función para guardar perfiles
function Save-Profiles($profiles) {
    try {
        $profiles | Export-Clixml -Path $configPath -Force
        return $true
    }
    catch {
        Write-Host "Error guardando perfiles: $_" -ForegroundColor Red
        return $false
    }
}

# Función para crear formulario de gestión de perfiles
function Show-ProfileManager {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Gestión de Perfiles de Conexión"
    $form.Size = New-Object System.Drawing.Size(700, 500)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    # Cargar perfiles existentes
    $profiles = Load-Profiles

    # Lista para perfiles
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Location = New-Object System.Drawing.Point(20, 20)
    $listView.Size = New-Object System.Drawing.Size(650, 350)
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.FullRowSelect = $true
    $listView.MultiSelect = $false
    $listView.GridLines = $true
    $listView.Columns.Add("Mostrar", 60) | Out-Null
    $listView.Columns.Add("Nombre", 150) | Out-Null
    $listView.Columns.Add("Servidor", 120) | Out-Null
    $listView.Columns.Add("Base de Datos", 120) | Out-Null
    $listView.Columns.Add("Documento", 100) | Out-Null
    $form.Controls.Add($listView)

    # Cargar datos en la lista
    foreach ($profile in $profiles) {
        $item = New-Object System.Windows.Forms.ListViewItem
        $item.Text = if ($profile.Visible) {"✓"} else {""}
        $item.SubItems.Add($profile.Name) | Out-Null
        $item.SubItems.Add($profile.Server) | Out-Null
        $item.SubItems.Add($profile.Database) | Out-Null
        $item.SubItems.Add($profile.DefaultDocument) | Out-Null
        $item.Tag = $profile
        $listView.Items.Add($item) | Out-Null
    }

    # Botones
    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Location = New-Object System.Drawing.Point(20, 380)
    $btnAdd.Size = New-Object System.Drawing.Size(100, 30)
    $btnAdd.Text = "Agregar Nuevo"
    $form.Controls.Add($btnAdd)

    $btnEdit = New-Object System.Windows.Forms.Button
    $btnEdit.Location = New-Object System.Drawing.Point(130, 380)
    $btnEdit.Size = New-Object System.Drawing.Size(100, 30)
    $btnEdit.Text = "Editar"
    $form.Controls.Add($btnEdit)

    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Location = New-Object System.Drawing.Point(240, 380)
    $btnDelete.Size = New-Object System.Drawing.Size(100, 30)
    $btnDelete.Text = "Eliminar"
    $form.Controls.Add($btnDelete)

    $btnToggle = New-Object System.Windows.Forms.Button
    $btnToggle.Location = New-Object System.Drawing.Point(350, 380)
    $btnToggle.Size = New-Object System.Drawing.Size(150, 30)
    $btnToggle.Text = "Alternar Visibilidad"
    $form.Controls.Add($btnToggle)

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Location = New-Object System.Drawing.Point(520, 380)
    $btnOK.Size = New-Object System.Drawing.Size(100, 30)
    $btnOK.Text = "Guardar"
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnOK
    $form.Controls.Add($btnOK)

    # Evento para agregar perfil
    $btnAdd.Add_Click({
        $newProfile = Show-ConnectionForm -EditMode $false
        if ($newProfile) {
            $item = New-Object System.Windows.Forms.ListViewItem
            $item.Text = if ($newProfile.Visible) {"✓"} else {""}
            $item.SubItems.Add($newProfile.Name) | Out-Null
            $item.SubItems.Add($newProfile.Server) | Out-Null
            $item.SubItems.Add($newProfile.Database) | Out-Null
            $item.SubItems.Add($newProfile.DefaultDocument) | Out-Null
            $item.Tag = $newProfile
            $listView.Items.Add($item) | Out-Null
        }
    })

    # Evento para editar perfil
    $btnEdit.Add_Click({
        if ($listView.SelectedItems.Count -gt 0) {
            $selectedItem = $listView.SelectedItems[0]
            $updatedProfile = Show-ConnectionForm -EditMode $true -Profile $selectedItem.Tag
            if ($updatedProfile) {
                $selectedItem.Text = if ($updatedProfile.Visible) {"✓"} else {""}
                $selectedItem.SubItems[1].Text = $updatedProfile.Name
                $selectedItem.SubItems[2].Text = $updatedProfile.Server
                $selectedItem.SubItems[3].Text = $updatedProfile.Database
                $selectedItem.SubItems[4].Text = $updatedProfile.DefaultDocument
                $selectedItem.Tag = $updatedProfile
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Seleccione un perfil para editar",
                "Editar Perfil",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })

    # Evento para eliminar perfil
    $btnDelete.Add_Click({
        if ($listView.SelectedItems.Count -gt 0) {
            $listView.Items.Remove($listView.SelectedItems[0])
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Seleccione un perfil para eliminar",
                "Eliminar Perfil",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })

    # Evento para alternar visibilidad
    $btnToggle.Add_Click({
        if ($listView.SelectedItems.Count -gt 0) {
            $selectedItem = $listView.SelectedItems[0]
            $profile = $selectedItem.Tag
            $profile.Visible = -not $profile.Visible
            $selectedItem.Text = if ($profile.Visible) {"✓"} else {""}
            $selectedItem.Tag = $profile
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Seleccione un perfil para cambiar visibilidad",
                "Visibilidad",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Recopilar perfiles actualizados
        $updatedProfiles = @()
        foreach ($item in $listView.Items) {
            $updatedProfiles += $item.Tag
        }
        return $updatedProfiles
    }
    return $null
}

# Función para crear/editar perfiles
function Show-ConnectionForm {
    param(
        [bool]$EditMode = $false,
        [hashtable]$Profile = $null
    )
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ($EditMode) {"Editar Perfil"} else {"Nuevo Perfil"}
    $form.Size = New-Object System.Drawing.Size(450, 400)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    # Campos del formulario
    $labelName = New-Object System.Windows.Forms.Label
    $labelName.Location = New-Object System.Drawing.Point(20, 20)
    $labelName.Size = New-Object System.Drawing.Size(150, 20)
    $labelName.Text = "Nombre del Perfil:"
    $form.Controls.Add($labelName)

    $textName = New-Object System.Windows.Forms.TextBox
    $textName.Location = New-Object System.Drawing.Point(180, 20)
    $textName.Size = New-Object System.Drawing.Size(230, 20)
    if ($Profile) { $textName.Text = $Profile.Name }
    $form.Controls.Add($textName)

    $labelServer = New-Object System.Windows.Forms.Label
    $labelServer.Location = New-Object System.Drawing.Point(20, 60)
    $labelServer.Size = New-Object System.Drawing.Size(150, 20)
    $labelServer.Text = "Servidor/IP:"
    $form.Controls.Add($labelServer)

    $textServer = New-Object System.Windows.Forms.TextBox
    $textServer.Location = New-Object System.Drawing.Point(180, 60)
    $textServer.Size = New-Object System.Drawing.Size(230, 20)
    if ($Profile) { $textServer.Text = $Profile.Server }
    $form.Controls.Add($textServer)

    $labelDB = New-Object System.Windows.Forms.Label
    $labelDB.Location = New-Object System.Drawing.Point(20, 100)
    $labelDB.Size = New-Object System.Drawing.Size(150, 20)
    $labelDB.Text = "Base de Datos:"
    $form.Controls.Add($labelDB)

    $textDB = New-Object System.Windows.Forms.TextBox
    $textDB.Location = New-Object System.Drawing.Point(180, 100)
    $textDB.Size = New-Object System.Drawing.Size(230, 20)
    if ($Profile) { $textDB.Text = $Profile.Database }
    $form.Controls.Add($textDB)

    $labelUser = New-Object System.Windows.Forms.Label
    $labelUser.Location = New-Object System.Drawing.Point(20, 140)
    $labelUser.Size = New-Object System.Drawing.Size(150, 20)
    $labelUser.Text = "Usuario:"
    $form.Controls.Add($labelUser)

    $textUser = New-Object System.Windows.Forms.TextBox
    $textUser.Location = New-Object System.Drawing.Point(180, 140)
    $textUser.Size = New-Object System.Drawing.Size(230, 20)
    if ($Profile) { $textUser.Text = $Profile.User }
    $form.Controls.Add($textUser)

    $labelPass = New-Object System.Windows.Forms.Label
    $labelPass.Location = New-Object System.Drawing.Point(20, 180)
    $labelPass.Size = New-Object System.Drawing.Size(150, 20)
    $labelPass.Text = "Contraseña:"
    $form.Controls.Add($labelPass)

    $textPass = New-Object System.Windows.Forms.TextBox
    $textPass.Location = New-Object System.Drawing.Point(180, 180)
    $textPass.Size = New-Object System.Drawing.Size(230, 20)
    $textPass.PasswordChar = '*'
    if ($Profile) { $textPass.Text = $Profile.Password }
    $form.Controls.Add($textPass)

    $labelDoc = New-Object System.Windows.Forms.Label
    $labelDoc.Location = New-Object System.Drawing.Point(20, 220)
    $labelDoc.Size = New-Object System.Drawing.Size(150, 20)
    $labelDoc.Text = "Documento Predeterminado:"
    $form.Controls.Add($labelDoc)

    $textDoc = New-Object System.Windows.Forms.TextBox
    $textDoc.Location = New-Object System.Drawing.Point(180, 220)
    $textDoc.Size = New-Object System.Drawing.Size(230, 20)
    if ($Profile) { $textDoc.Text = $Profile.DefaultDocument } else { $textDoc.Text = "300000000" }
    $form.Controls.Add($textDoc)

    $checkVisible = New-Object System.Windows.Forms.CheckBox
    $checkVisible.Location = New-Object System.Drawing.Point(20, 260)
    $checkVisible.Size = New-Object System.Drawing.Size(390, 20)
    $checkVisible.Text = "Mostrar en pantalla principal"
    if ($Profile) { $checkVisible.Checked = $Profile.Visible } else { $checkVisible.Checked = $true }
    $form.Controls.Add($checkVisible)

    # Botones
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Location = New-Object System.Drawing.Point(120, 300)
    $btnOK.Size = New-Object System.Drawing.Size(100, 30)
    $btnOK.Text = "Aceptar"
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnOK
    $form.Controls.Add($btnOK)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(230, 300)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
    $btnCancel.Text = "Cancelar"
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $btnCancel
    $form.Controls.Add($btnCancel)

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return @{
            Name = $textName.Text
            Server = $textServer.Text
            Database = $textDB.Text
            User = $textUser.Text
            Password = $textPass.Text
            DefaultDocument = $textDoc.Text
            Visible = $checkVisible.Checked
        }
    }
    return $null
}

# Función principal con GUI
function Show-MainForm {
    $mainForm = New-Object System.Windows.Forms.Form
    $mainForm.Text = "Consultas REC/NDC v$scriptVersion ($daysLeft días de licencia)"
    $mainForm.Size = New-Object System.Drawing.Size(800, 500)
    $mainForm.StartPosition = "CenterScreen"
    $mainForm.MinimumSize = New-Object System.Drawing.Size(700, 450)

    # Variable para mantener la conexión actual
    $global:currentConnection = $null
    $global:currentProfile = $null

    # Panel para botones de perfiles
    $profilePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $profilePanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $profilePanel.Height = 50
    $profilePanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $profilePanel.AutoScroll = $true
    $mainForm.Controls.Add($profilePanel)

    # Barra de estado
    $statusBar = New-Object System.Windows.Forms.StatusBar
    $statusBar.Text = "Licencia activa | Seleccione un perfil"
    $mainForm.Controls.Add($statusBar)

    # Panel de controles 
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = [System.Windows.Forms.DockStyle]::Top
    $panel.Height = 110
    $panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $mainForm.Controls.Add($panel)

    # Etiqueta y campo para Documento
    $labelDoc = New-Object System.Windows.Forms.Label
    $labelDoc.Location = New-Object System.Drawing.Point(20, 20)
    $labelDoc.Size = New-Object System.Drawing.Size(100, 20)
    $labelDoc.Text = "Documento:"
    $panel.Controls.Add($labelDoc)

    $textDoc = New-Object System.Windows.Forms.TextBox
    $textDoc.Location = New-Object System.Drawing.Point(120, 20)
    $textDoc.Size = New-Object System.Drawing.Size(200, 20)
    $textDoc.Text = "300000000"
    $panel.Controls.Add($textDoc)

    # Etiqueta y campo para Concepto (fijo)
    $labelConcept = New-Object System.Windows.Forms.Label
    $labelConcept.Location = New-Object System.Drawing.Point(20, 50)
    $labelConcept.Size = New-Object System.Drawing.Size(100, 20)
    $labelConcept.Text = "Concepto:"
    $panel.Controls.Add($labelConcept)

    $textConcept = New-Object System.Windows.Forms.TextBox
    $textConcept.Location = New-Object System.Drawing.Point(120, 50)
    $textConcept.Size = New-Object System.Drawing.Size(100, 20)
    $textConcept.Text = "REC"
    $textConcept.Enabled = $false
    $textConcept.BackColor = [System.Drawing.Color]::LightGray
    $panel.Controls.Add($textConcept)

    # Panel de estado compacto
    $statusPanel = New-Object System.Windows.Forms.Panel
    $statusPanel.Location = New-Object System.Drawing.Point(350, 20)
    $statusPanel.Size = New-Object System.Drawing.Size(300, 50)
    $statusPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $panel.Controls.Add($statusPanel)

    # Etiqueta para título de estado
    $labelStatusTitle = New-Object System.Windows.Forms.Label
    $labelStatusTitle.Location = New-Object System.Drawing.Point(10, 15)
    $labelStatusTitle.Size = New-Object System.Drawing.Size(100, 20)
    $labelStatusTitle.Text = "(c_Status):"
    $labelStatusTitle.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
    $statusPanel.Controls.Add($labelStatusTitle)

    # Etiqueta para valor de estado
    $labelStatusValue = New-Object System.Windows.Forms.Label
    $labelStatusValue.Location = New-Object System.Drawing.Point(120, 10)
    $labelStatusValue.Size = New-Object System.Drawing.Size(150, 30)
    $labelStatusValue.Text = ""
    $labelStatusValue.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    $labelStatusValue.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $statusPanel.Controls.Add($labelStatusValue)

    # Botón de consulta
    $btnQuery = New-Object System.Windows.Forms.Button
    $btnQuery.Location = New-Object System.Drawing.Point(20, 80)
    $btnQuery.Size = New-Object System.Drawing.Size(120, 25)
    $btnQuery.Text = "Ejecutar Consulta"
    $btnQuery.Enabled = $false  # Inicialmente deshabilitado
    $panel.Controls.Add($btnQuery)

    # Botón para cambiar estado
    $btnChangeStatus = New-Object System.Windows.Forms.Button
    $btnChangeStatus.Location = New-Object System.Drawing.Point(150, 80)
    $btnChangeStatus.Size = New-Object System.Drawing.Size(150, 25)
    $btnChangeStatus.Text = "Cambiar DCO → DPE"
    $btnChangeStatus.Enabled = $false
    $btnChangeStatus.BackColor = [System.Drawing.Color]::LightGreen
    $panel.Controls.Add($btnChangeStatus)

    
    # Grid para resultados
    $dataGrid = New-Object System.Windows.Forms.DataGridView
    $dataGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $dataGrid.AllowUserToAddRows = $false
    $dataGrid.AllowUserToDeleteRows = $false
    $dataGrid.ReadOnly = $true
    $dataGrid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $dataGrid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $mainForm.Controls.Add($dataGrid)

    # Función para actualizar botones de perfil
    function Update-ProfileButtons {
        $profilePanel.Controls.Clear()
        
        # Cargar perfiles visibles
        $profiles = Load-Profiles | Where-Object { $_.Visible }
        
        # Crear botones para perfiles visibles
        foreach ($profile in $profiles) {
            $btnProfile = New-Object System.Windows.Forms.Button
            $btnProfile.Text = $profile.Name
            $btnProfile.Size = New-Object System.Drawing.Size(150, 30)
            $btnProfile.Margin = New-Object System.Windows.Forms.Padding(5)
            $btnProfile.Tag = $profile
            $btnProfile.BackColor = [System.Drawing.Color]::LightBlue
            $btnProfile.Add_Click({
                $profile = $this.Tag
                $global:currentProfile = $profile
                
                # Actualizar barra de estado
                $statusBar.Text = "Perfil: $($profile.Name) | Servidor: $($profile.Server) | BD: $($profile.Database)"
                
                # Establecer documento predeterminado
                $textDoc.Text = $profile.DefaultDocument
                
                # Habilitar botón de consulta
                $btnQuery.Enabled = $true
                
                # Limpiar resultados previos
                $dataGrid.DataSource = $null
                $labelStatusValue.Text = ""
                $btnChangeStatus.Enabled = $false
                
                # Mostrar notificación
                $statusBar.Text = "Perfil '$($profile.Name)' cargado. Documento: $($profile.DefaultDocument)"
            })
            $profilePanel.Controls.Add($btnProfile)
        }
        
        # Botón para administrar perfiles
        $btnManage = New-Object System.Windows.Forms.Button
        $btnManage.Text = "Administrar Perfiles"
        $btnManage.Size = New-Object System.Drawing.Size(150, 30)
        $btnManage.Margin = New-Object System.Windows.Forms.Padding(5)
        $btnManage.BackColor = [System.Drawing.Color]::LightGreen
        $btnManage.Add_Click({
            $updatedProfiles = Show-ProfileManager
            if ($updatedProfiles) {
                Save-Profiles $updatedProfiles
                # Actualizar botones sin recargar ventana
                Update-ProfileButtons
            }
        })
        $profilePanel.Controls.Add($btnManage)
    }

    # Inicializar botones de perfil
    Update-ProfileButtons

    # Función para cerrar conexiones activas
    function Close-CurrentConnection {
        if ($global:currentConnection -ne $null -and $global:currentConnection.State -eq 'Open') {
            $global:currentConnection.Close()
        }
        $global:currentConnection = $null
    }

    # Evento para ejecutar consulta 
    $btnQuery.Add_Click({
        if (-not $global:currentProfile) {
            [System.Windows.Forms.MessageBox]::Show(
                "Seleccione un perfil primero",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }
        
        $dataGrid.DataSource = $null
        $labelStatusValue.Text = ""
        $btnChangeStatus.Enabled = $false
        $statusBar.Text = "Ejecutando consulta..."
        
        # Cerrar conexión existente antes de abrir nueva
        Close-CurrentConnection
        
        try {
            # Construir cadena de conexión
            $connString = "Server=$($global:currentProfile.Server);" +
                            "Database=$($global:currentProfile.Database);" +
                            "User Id=$($global:currentProfile.User);"
            
            if (-not [string]::IsNullOrEmpty($global:currentProfile.Password)) {
                $connString += "Password=$($global:currentProfile.Password);"
            }
            
            $connection = New-Object System.Data.SqlClient.SqlConnection
            $connection.ConnectionString = $connString
            $connection.Open()
            
            # Guardar referencia a la conexión actual
            $global:currentConnection = $connection
            
            # Crear comando
            $command = $connection.CreateCommand()
            $command.CommandText = @"
                SELECT * 
                FROM MA_INVENTARIO
                WHERE c_CONCEPTO = 'REC' 
                    AND c_DOCUMENTO = '$($textDoc.Text)'
"@
            
            # Ejecutar consulta y cargar datos
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
            $dataset = New-Object System.Data.DataSet
            $adapter.Fill($dataset) | Out-Null
            
            if ($dataset.Tables[0].Rows.Count -gt 0) {
                $dataGrid.DataSource = $dataset.Tables[0]
                $statusBar.Text = "$($dataset.Tables[0].Rows.Count) registros encontrados"
                
                # Obtener y mostrar el valor de c_Status del primer registro
                $cStatus = $dataset.Tables[0].Rows[0]["c_Status"]
                $labelStatusValue.Text = $cStatus
                
                # Cambiar color según el estado
                if ($cStatus -eq "A") {
                    $labelStatusValue.ForeColor = [System.Drawing.Color]::Green
                } elseif ($cStatus -eq "R") {
                    $labelStatusValue.ForeColor = [System.Drawing.Color]::Red
                } else {
                    $labelStatusValue.ForeColor = [System.Drawing.Color]::DarkBlue
                }
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "No se encontraron registros",
                    "Resultados",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                $statusBar.Text = "0 registros encontrados"
                $labelStatusValue.Text = "N/A"
                $labelStatusValue.ForeColor = [System.Drawing.Color]::Gray
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error en la consulta: $_",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            $statusBar.Text = "Error en la consulta"
            $labelStatusValue.Text = "Error"
            $labelStatusValue.ForeColor = [System.Drawing.Color]::DarkRed
        }
    })

    # Evento para cambiar estado DCO → DPE usando c_DOCUMENTO
    $btnChangeStatus.Add_Click({
    if ($dataGrid.SelectedRows.Count -gt 0) {
        $selectedRow = $dataGrid.SelectedRows[0].DataBoundItem
        $documento = $selectedRow["c_DOCUMENTO"]
        $concepto = $selectedRow["c_CONCEPTO"]
        
        # Verificar que el estado actual es DCO
        $currentStatus = $selectedRow["c_Status"]
        if ($currentStatus -ne "DCO") {
            [System.Windows.Forms.MessageBox]::Show(
                "Solo se puede cambiar el estado de registros con estado DCO",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        # --- CONFIRMACIÓN ADICIONAL ---
        $confirmation = [System.Windows.Forms.MessageBox]::Show(
            "¿Está seguro de activar la REC $($documento)?`n`nEsta acción cambiará el estado de DCO → DPE",
            "Éxito",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        
        if ($confirmation -ne [System.Windows.Forms.DialogResult]::Yes) {
            return
        }

            # Cerrar conexión existente antes de abrir nueva
            Close-CurrentConnection
            
            try {
                # Construir cadena de conexión
                $connString = "Server=$($global:currentProfile.Server);" +
                                "Database=$($global:currentProfile.Database);" +
                                "User Id=$($global:currentProfile.User);"
                
                if (-not [string]::IsNullOrEmpty($global:currentProfile.Password)) {
                    $connString += "Password=$($global:currentProfile.Password);"
                }
                
                $connection = New-Object System.Data.SqlClient.SqlConnection
                $connection.ConnectionString = $connString
                $connection.Open()
                
                # Guardar referencia a la conexión actual
                $global:currentConnection = $connection
                
                # Crear comando de actualización usando c_DOCUMENTO
                $command = $connection.CreateCommand()
                $command.CommandText = @"
                    UPDATE MA_INVENTARIO
                    SET c_Status = 'DPE'
                    WHERE c_DOCUMENTO = '$documento'
                        AND c_CONCEPTO = '$concepto'
"@
                $rowsAffected = $command.ExecuteNonQuery()
                
                if ($rowsAffected -gt 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Estado actualizado correctamente de DCO a DPE para el documento $documento",
                    "Éxito",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                    
                    # Actualizar todos los registros con este documento
                    foreach ($row in $dataGrid.Rows) {
                        if ($row.Cells["c_DOCUMENTO"].Value -eq $documento) {
                            $row.Cells["c_Status"].Value = "DPE"
                        }
                    }
                    
                    # Actualizar el estado mostrado
                    $labelStatusValue.Text = "DPE"
                    $labelStatusValue.ForeColor = [System.Drawing.Color]::DarkGreen
                    
                    # Refrescar el DataGridView
                    $dataGrid.Refresh()
                }
                else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "No se pudo actualizar el estado",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                }
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error al actualizar el estado: $_",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        }
    })


    # Manejar tecla Enter en campo de documento
    $textDoc.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $btnQuery.PerformClick()
        }
    })

    # Evento para mostrar el estado cuando se selecciona un registro
    $dataGrid.Add_SelectionChanged({
        if ($dataGrid.SelectedRows.Count -gt 0) {
            $selectedRow = $dataGrid.SelectedRows[0].DataBoundItem
            $cStatus = $selectedRow["c_Status"]
            $labelStatusValue.Text = $cStatus
            
            # Cambiar color según el estado
            if ($cStatus -eq "A") {
                $labelStatusValue.ForeColor = [System.Drawing.Color]::Green
            } elseif ($cStatus -eq "R") {
                $labelStatusValue.ForeColor = [System.Drawing.Color]::Red
            } else {
                $labelStatusValue.ForeColor = [System.Drawing.Color]::DarkBlue
            }
            
            # Habilitar botón solo si el estado es DCO
            $btnChangeStatus.Enabled = ($cStatus -eq "DCO")
        }
    })

    # Cerrar conexión al salir de la aplicación
    $mainForm.Add_FormClosing({
        Close-CurrentConnection
    })

    # Mostrar formulario
    $mainForm.Add_Shown({ $textDoc.Select() })
    $mainForm.ShowDialog() | Out-Null
}

# --- Inicio del script ---

# Si no hay perfiles, crear uno predeterminado
$profiles = Load-Profiles
if ($profiles.Count -eq 0) {
    $defaultProfile = @{
        Name = "Perfil Predeterminado"
        Server = "localhost"
        Database = "MAESTRA"
        User = "sa"
        Password = ""
        DefaultDocument = "300000000"
        Visible = $true
    }
    Save-Profiles @($defaultProfile)
}

# Mostrar interfaz principal
Show-MainForm