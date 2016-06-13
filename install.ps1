
# Este Script es utilizado para instalar el módulo
#
#  Descargamos los ficheros del módulo a un directorio temporal del usuario
#  para luego lanzar la instalación del módulo.
#  Previamente desinstalamos el múdulo antiguo y directorio temporal

# nombre del módulo a copiar
$nombreModulo="modulo-seguridad-powershell"

# directorio donde se ubican los modulos de usuario
$DirModulo = (($env:PSModulePath).Split(";") | where {$_ -match $env:USERNAME}) + "\" +$nombreModulo

# nombre de ficheros que componen el módulo
$listaficheros=@("LICENSE",
                 "README.md",
                 "install.ps1",
                 "modulo-seguridad-powershell.psd1",
                 "modulo-seguridad-powershell.psm1")

#url del módulo publicado en github
$UrlModulo = "https://raw.githubusercontent.com/kiarsus/modulo-seguridad-powershell/master/"

# directorio temporal donde descargaremos el modulo antes de instalarlo
$Dirtemporal = $env:TMP + "\" + $nombreModulo + "\"

# eliminamos el módulo en el caso de que existiera
Remove-Module -Name $nombreModulo -ErrorAction SilentlyContinue

# eliminamos el directorio del modulo
rm $DirModulo -Force -Recurse -ErrorAction SilentlyContinue

# eliminamos el directorio temporal y todo su contenido
rm $Dirtemporal -Force -Recurse -ErrorAction SilentlyContinue

# creamos el directorio temporal
$basura= md $Dirtemporal -ErrorAction SilentlyContinue

# creamos la instancia del navegador
$navegador = New-Object System.Net.WebClient

# Descargamos cada uno de los archivos del módulo del repositorio
""
Write-Host "Descargando los ficheros de modulo-seguridad-powershell: " -ForegroundColor Green
foreach ($item in $listaficheros)
{
    Write-Host  ".. " + $item  -ForegroundColor Green
    $navegador.DownloadFile( $UrlModulo + $item, $Dirtemporal + $item)
}
#cd $Dirtemporal 
#Install-Module -ModulePath ($nombreModulo + ".psm1")
 mv $Dirtemporal $DirModulo -Force 
$basura = Import-Module -Name $nombreModulo -ErrorAction SilentlyContinue
""
Write-Host "Se han importado los siguiente comandos: " -ForegroundColor Green
Get-Command -Module $nombreModulo -ErrorAction SilentlyContinue
# eliminamos las variables usadas en el script
Remove-Variable nombreModulo, DirModulo, listaficheros, UrlModulo, Dirtemporal, basura, navegador, item


