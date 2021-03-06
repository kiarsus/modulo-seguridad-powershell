
#
#   El presente fichero forma parte del módulo de PowerShell, 
# “modulo-seguridad-powershell”, desarrollado para el Trabajo 
# Fin de Grado del “Curso de adaptación al Grado de Ingeniería
# Informática, de la Universidad Internacional de la Rioja.
#
#   Dicho trabajo se encuentra Publicado en el repositorio 
# Git-Hub, bajo la licencia GNU General Public License.
# https://github.com/kiarsus/modulo-seguridad-powershell
#   Trabajo realizado única y exclusivamente por el Alumno: 
# Enrique Parras Garrido.
#
#
#
#
# El presente módulo de PowerShell intenta solventar la falta de 
# herramientas para el profesional de seguridad TIC a la hora de 
# trabajar con los sistemas operativos Windows, para análisis 
# forense, monitorización de eventos y contención de determinados 
# ataques.
#
#
# El presente módulo lo dividimos en varios apartados atendiendo a 
# los recursos usados para la recogida de evidencias, monitorización 
# de eventos y la contención de determinados ataques.
#
# Inicialmente en la memoria se contemplaron los apartados
#
#    * Memoria (procesos y servicios)
#    * Almacenamiento en disco
#    * Registro de Windows
#    * Red
#
#
# Pero hay funciones que escapan a esta clasificación, ya que hacen 
# uso de diferentes recursos clasificados en varios apartados.
# 
#    * RansomWare
#    * Red
#    * Memoria (procesos y servicios)
#    * Almacenamiento en disco
#        - Trabajar con Almacenes de correo Outlook (Ficheros .PST) 
#        - Listado y eliminación de ficheros temporales 
#    * Registro de Windows
#    * Memoria (procesos y servicios)








# ------------------------- RansomWare ------------------------- 
# Este apartado comprende los recursos para poder detectar y detener
# las acciones de un RansomWare:
#
# La principal función de este apartado crea una regla que supervisa 
# un directorio y los elementos que contiene ante los eventos de 
# creación, eliminado, modificación y cambio de nombre.
# Cuando se detecta el evento programado se procede a desactivar la 
# cuenta del usuario y a cerrar las conexiones que tenga abiertas.
# Existe la posibilidad de especificar un nombre de fichero como 
# log.
#
#  Para que la función principal de este apartado sea funcional 
# se apoya en otros comandos y una estructura de datos que 
# permite gestionar las diferentes reglas RansomWare definidas.
# 
# 
#-----------------------------------------------------------
#
#
#
#
#












<#
.Synopsis
   Comprueba si existe una cuenta de usuario.
.DESCRIPTION
   Comprueba si existe una cuenta de usuario.
   Como parámetro acepta el nombre de cuenta de un usuario.

.EXAMPLE
    Test-AccountUserName -AccountUserName "juanito"
    Devuelve $true si existe la cuenta de usuario "juanito"
    En caso contrario devuelve $false.


#>

function Test-AccountUserName
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
        # Nombre de cuenta de usuario a comprobar.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If($_ -ne ""){$true}else{Throw "El argumento -AccountUserName no puede estar vacío:"}})]        
        [string]$AccountUserName
    )

 
    # A continuación recuperamos las cuentas de usuario
    # y filtramos por el nombre $AccountUserName.
    
    if ($null -eq (Get-WmiObject  Win32_UserAccount | ? {$_.name -eq $AccountUserName} ))
    {
        return $false
    }
    else
    {
        return $true
    }
    
}














<#
.Synopsis
   Bloquea una cuenta de usuario.
.DESCRIPTION
   Bloquea una cuenta de usuario. El nombre de la cuenta lo pasamos
   como parámetro.
   El bloqueo de la cuenta no implica el cierre de sesión.
.EXAMPLE
    Lock-AccountUserName -AccountUserName "juanito"
    Bloquea la cuenta de usuario, con nombre "juanito"


.EXAMPLE
    $usuarios_abusos = @("juanito","admin","jue")
    C:\PS>$usuarios_abusos |foreach-object { Lock-AccountUserName $_}

    Bloquea la cuenta de los usuarios incluidos en el array $usuarios_abusos.


#>

function Lock-AccountUserName
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Nombre de cuenta del usuario a bloquear.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-AccountUserName $_){$true}else{Throw "El usuario '$_' no existe."}})]        
        [string]$AccountUserName
    )

 
    # A continuación recuperamos las cuentas de usuario
    # y filtramos por el nombre $AccountUserName.
    # Actualizamos la cuenta de usuario con las propiedades Disabled y Lockout a $true
    # (los demás parámetros quedan igual).


    # Para evitar que el usuario que ejecuta el script sea bloqueado, hacemos una comprobación previa.
    if ($env:USERNAME -ne $AccountUserName){
        Get-WmiObject  Win32_UserAccount | ? {$_.name -eq $AccountUserName} | Set-WmiInstance -Arguments @{Disabled=$true; Lockout=$true}
    }
    # Para más información de las propiedades de las cuentas de usuario 
    # (Get-WmiObject  Win32_UserAccount)[0] | select *
    
}






<#
.Synopsis
   Desbloquea una cuenta de usuario.
.DESCRIPTION
   Desbloquea una cuenta de un usuario. Debemos proporcionar el nombre de la cuenta.
.EXAMPLE
   Unlock-AccountUserName -AccountUserName "juanito"


   El ejemplo desbloquea la cuenta de usuario, con nombre "juanito"


.EXAMPLE
   $usuarios_abusos = @("juanito","admin","jue")
   C:\PS>$usuarios_abusos |foreach-object { Unlock-AccountUserName $_}

   
   El ejemplo desbloquea la cuenta de los usuarios incluidos en el array $usuarios_abusos


#>

function Unlock-AccountUserName
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Nombre de la cuenta de usuario a desbloquear.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-AccountUserName $_){$true}else{Throw "El usuario '$_' no existe."}})]        
        [string]$AccountUserName
    )

 
    # A continuación recuperamos las cuentas de usuario
    # y filtramos por el nombre $AccountUserName.
    # Actualizamos la cuenta de usuario con las propiedades Disabled y Lockout a $false
    # (los demás parámetros quedan igual).
    Get-WmiObject  Win32_UserAccount | ? {$_.name -eq $AccountUserName} | Set-WmiInstance  -Arguments @{Disabled=$false; Lockout=$false} 
    # Para más información de las propiedades de las cuentas de usuario 
    # (Get-WmiObject  Win32_UserAccount)[0] | select *
    
}





<#
.Synopsis
   Comprueba si existe una regla RansomWare. 

.DESCRIPTION
   Comprueba si existe una regla RansomWare. 

.EXAMPLE    
    Test-RansomWareRuleName "Created_c:\prueba\_senuelo\*.*"

    El comando comprueba si existe la regla "Created_c:\prueba\_senuelo\*.*".
    En caso afirmativo devuelve $true.
    En caso negativo devuelve $false.
    

#>
function Test-RansomWareRuleName

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Nombre de la regla RansomWare
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$RansomWareRuleName
    )

    # Para almacenar las reglas de RansomWare se ha creado una estructura dentro de las 
    # variables globales llamada "ReglasRansomWare".
    # Esta declaración es debida a la necesidad de ser accedida.
    # Es un array y cada elemento es una etructura que se compone de:
    #            - nombre de la regla.
    #            - cadena de inicialización.
    #            - fichero log.                 
    
    if ( ($Global:ReglasRansomWare | where {$_.Regla -eq $RansomWareRuleName})  -eq $null  )
    {
        return $false
    } 
    else 
    { 
        return $true
    }
}









<#
.Synopsis
    Obtiene los ficheros abiertos a través de la red. 

.DESCRIPTION
    Obtiene los ficheros abiertos a través de la red. 

.EXAMPLE    
    Get-NetOpenFiles 

    Obtiene los ficheros abiertos a través de la red

.EXAMPLE
     Get-NetOpenFiles | where-object { $_.user -eq "manolito"}
    
    Obtiene los ficheros abiertos a través de la red por el usuario "manolito"
    



#>
function Get-NetOpenFiles

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

    )



    # debe ejecutarse como administrador
    # https://social.technet.microsoft.com/Forums/office/en-US/e03753fa-3f93-4677-ae21-3480dce103b7/help-with-powershell-script-to-close-open-files?forum=winserverpowershell
    $adsi = [adsi]"WinNT://./LanmanServer"


    $RecursosAbiertos = $adsi.psbase.Invoke("resources")
    
    $NetOpenFiles = @()

    foreach ($item in $RecursosAbiertos)
    {
        $obj = New-Object PSObject 
        $obj | Add-Member user $item.gettype().invokeMember("User","GetProperty",$null,$item,$null)
        $obj | Add-Member FilePath $item.gettype().invokeMember("Path","GetProperty",$null,$item,$null)
        $obj | Add-Member IdSession $item.gettype().invokeMember("Name","GetProperty",$null,$item,$null)
        $obj | Add-Member NumLock $item.gettype().invokeMember("LockCount","GetProperty",$null,$item,$null)
        $NetOpenFiles = $NetOpenFiles + $obj
    }
    

    
    $NetOpenFiles

}








<#
.Synopsis
    Obtiene el nombre del propietario de un fichero o directorio 

.DESCRIPTION
    Obtiene el nombre del propietario de un fichero o directorio 

.EXAMPLE    
    Get-FileOwner c:\prueba 

    Obtiene el propietario del directorio "c:\prueba"

.EXAMPLE    
    Get-FileOwner c:\prueba\sss.txt

    Obtiene el propietario del fichero "c:\prueba\sss.txt"




#>
function Get-FileOwner 

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Especifica la ruta del fichero o directorio
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero o directorio: $_"}})]        
        [string]$Path,
        # Cuando se especifica este parámetro sólo se devuelve el nombre de usuario.
        # Por defecto devuelve el nombre de usuario y el dominio "dominio\usuario".
        [Parameter()]
        [switch]$UserOnly


    )

    if ($UserOnly) 
    {
        (Get-Item $Path).GetAccessControl().Owner.Split("\")[1]
    }
    else 
    {
        (Get-Item $Path).GetAccessControl().Owner
    }



}









<#
.Synopsis
   Crea una regla de protección RansomWare. 

.DESCRIPTION
   Crea una regla de protección RansomWare. Es necesario indicar 
   el directorio a supervisar y al menos un evento a supervisar. 
   Como medida de respuesta se bloquea el usuario que desencadena el 
   evento y se cierran las sesiones que tenga establecida.

.EXAMPLE    
    new-RansomWareRule -PathDirectory "c:\compartido\e" -Filter "*.*" -Renamed

    El comando crea una regla RansomWare para el directorio "c:\compartido\e", con el filtro de elementos "*.*" 
    No aplica al contenido de los subdirectorios. 
    
    Inhabilita la cuenta del usuario, que cambie el nombre de un fichero o directorio incluidos en "c:\compartido\e".
        
.EXAMPLE    
    new-RansomWareRule -PathDirectory "c:\compartido\e" -Filter "*.ht*" -Created -Subdirectories -FileLog c:\log\RansomWare.log
    
    El comando crea una regla RansomWare para el directorio "c:\compartido\e". La regla se activa cada vez que 
    se crea un fichero, cuya extensión comience por "ht". Dicha regla tiene efecto en cualquiera de los subdirectorios
    y sus descendientes "c:\comporatido\e".   
     
        
    Inhabilita la cuenta del usuario, que cree un fichero o directorio con las características descritas.


#>
function new-RansomWareRule

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Directorio que se va a proteger con la regla.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el directorio: $_"}})]        
        [string]$PathDirectory,

        # Filtro que se va a aplicar al directorio a proteger, por defecto todo el contenido.
        [Parameter()]
        [String]$Filter="*.*",

        # Especifica si la regla se aplica a los subdirectorios de manera recursiva.
        [Parameter()]
        [switch]$Subdirectories=$false,
        
        # Especifica si se supervisa la creación de nuevos elementos.
        [Parameter()]
        [switch]$Created=$false,

        # Especifica si se supervisa la eliminación de elementos.
        [Parameter()]
        [switch]$Deleted=$false,

        # Especifica si se supervisa la modificación de elementos.
        [Parameter()]
        [switch]$Changed=$false,

        # Especifica si se supervisa el cambio de nombre de elementos.
        [Parameter()]
        [switch]$Renamed=$false,


        # Especifica ruta completa de un fichero log, en el que 
        # se volcarán los eventos detectados y las acciones realizadas.
        [ValidateScript({If(  (Test-Path $_.Substring(0,$_.LastIndexOf("\"))) -or ($_ -eq ""  ) ){$true}else{Throw "No se encuentra el directorio: $_"}})]        
        [string]$FileLog=""
    )
    

    # En Begin comprobamos que al menos se introduce un evento a supervisar y
    # definimos los bloques de ejecucion que responderan a cada uno de los eventos
    # de creación, eliminación, modificación y cambio de nombre de ficheros o directorios:
    # $BloqueEjecucionCreated
    # $BloqueEjecucionDeleted
    # $BloqueEjecucionChanged
    # $BloqueEjecucionRenamed
    Begin
    {


        # Si no se elige al menos un evento a supervisar, abortamos y mostramos error.
        if( -not ($Created -or $Deleted -or $Changed -or $Renamed) ){Throw "Al menos debe espeficicarse un evento de protección: -Created, -Deleted, -Changed o -Renamed. Ver ayuda."}

        #Fin de comprobación de parámetros
    

        # Se corresponde con el bloque de ejecución que va a ejecutarse cuando se
        # detecte un evento de creación.
        $BloqueEjecucionCreated= {
            # Obtenemos la hora en la que se genera el evento
            $EventHora = $Event.TimeGenerated
            # Obtenemos el nombre de la regla RansomWare
            $EventRegla =$Event.SourceIdentifier
            # Obtenemos el nombre completo del fichero o directorio que desencadena el evento
            $EventFicheroCreado = $Event.SourceArgs.FullPath
            # Obtenemos el nombre del usuario que desencadena el evento
            $EventUsuarioABloquear = Get-FileOwner -Path $Event.SourceArgs.FullPath -UserOnly
            # Obtenemos los identificadores de sesión smb del usuario que desencadena el evento.
            $EventSesionesABloquear =  (Get-SmbSession | where {$_.ClientUserName -eq (Get-FileOwner -Path $Event.SourceArgs.FullPath)}).SessionId
            # Obtenemos las direcciones IP desde donde el usuario desencadena el evento
            $EventSesionesABloquearIP =  (Get-SmbSession | where {$_.ClientUserName -eq (Get-FileOwner -Path $Event.SourceArgs.FullPath)}).ClientComputerName

            # Bloqueamos la cuenta de usuario que desencadenó la regla RansomWare.
            # Desconectamos las sesiones de red del usuario que creó el fichero no permitido.
            $pape = Lock-AccountUserName  $EventUsuarioABloquear
            $EventSesionesABloquear | ForEach-Object {Close-SmbSession  $_ -Force -Confirm:$false}

            # recuperamos el nombre del fichero log
            $EventFicheroLog = (Get-RansomWareRule | where-object { $_.regla -eq $EventRegla}).FicheroLog
        
            # Sólo en el caso de que especifiquemos un fichero log
            # Componemos la línea que vamos a escribir en el fichero log
            # y escribimos en él 
            if ($EventFicheroLog -ne "")
            {
                $linea =  "$EventHora | Regla: $EventRegla | Creado:  $EventFicheroCreado | Usuario a bloquear: $EventUsuarioABloquear | Sessiones remotas: $EventSesionesABloquear | Equipos remotos: $EventSesionesABloquearIP"
                Out-File -FilePath $EventFicheroLog -Append -InputObject $linea
            }


        } # fin de BloqueEjecucionCreated


        # Se corresponde con el bloque de ejecución que va a ejecutarse cuando se
        # detecte un evento de eliminación.
        $BloqueEjecucionDeleted= {

            # Obtenemos la hora en la que se genera el evento
            $EventHora = $Event.TimeGenerated
            # Obtenemos el nombre de la regla RansomWare
            $EventRegla =$Event.SourceIdentifier
            # Obtenemos el nombre completo del fichero o directorio que desencadena el evento
            $EventFicheroEliminado = $Event.SourceArgs.FullPath
            # Averiguamos el padre del fichero o diretorio eliminado
            $PadreFicheroEliminado = $EventFicheroEliminado.Substring(0, $EventFicheroEliminado.LastIndexOf("\") )
            # Recuperamos los usuarios que  tienen abierto el directorio padre.
            # Que son los usuarios candidatos a desencadenar el evento
            $EventUsuarioABloquear = Get-NetOpenFiles | Where-Object {$_.FilePath -eq $PadreFicheroEliminado} | ForEach-Object { $_.user}
            # Buscamos los usuarios que tiene abierto el directorio padre
            # Recuperamos el nombre del fichero log
            $EventFicheroLog = (Get-RansomWareRule | where-object { $_.regla -eq $EventRegla}).FicheroLog
            # Por cada uno de los usuario localizados, bloqueamos su cuenta.
            # Cerramos las sesiones de red y guardamos un registro en el log.
            foreach ($item in $EventUsuarioABloquear)
            {
                #Averiguamos los usuarios que ha podido eliminar el fichero o directorio 
                $EventSesionesABloquear  = (Get-SmbSession | where {$_.ClientUserName -eq ($env:COMPUTERNAME +"\" +  $item)}).SessionId
    
                # Obtenemos las direcciones IP desde donde el usuario desencadena el evento
                $EventSesionesABloquearIP = (Get-SmbSession | where {$_.ClientUserName -eq ($env:COMPUTERNAME +"\" +  $item)}).ClientComputerName
    
                # Bloqueamos los usuarios
                $pape = Lock-AccountUserName  $item
    
                # Cerramos las sesiones abiertas por cada uno de los usuarios
                $EventSesionesABloquear | ForEach-Object {Close-SmbSession  $_ -Force -Confirm:$false}
                        
                # Sólo en el caso de que especifiquemos un fichero log
                # Componemos la línea que vamos a escribir en el fichero log
                # y escribimos en el 
                if ($EventFicheroLog -ne ""){
                    $linea =  "$EventHora | Regla: $EventRegla | Eliminado:  $EventFicheroEliminado | Usuarios a bloquear: $item | Sessiones remotas: $EventSesionesABloquear | Equipos remotos: $EventSesionesABloquearIP "
                    Out-File -FilePath $EventFicheroLog -Append -InputObject $linea
                }   
            }
        } # fin de BloqueEjecucionDeleted



        # Se corresponde con el bloque de ejecución que va a ejecutarse cuando se
        # detecte un evento de modificación.
        $BloqueEjecucionChanged= {

            # Obtenemos la hora en la que se genera el evento
            $EventHora = $Event.TimeGenerated
            # Obtenemos el nombre de la regla RansomWare
            $EventRegla =$Event.SourceIdentifier
            # Obtenemos el nombre completo del fichero o directorio que desencadena el evento
            $EventFicheroCambiado = $Event.SourceArgs.FullPath
            # Averiguamos el padre del fichero o diretorio que desencadena el evento
            $PadreFicheroCambiado = $EventFicheroCambiado.Substring(0, $EventFicheroCambiado.LastIndexOf("\") )
            # Recuperamos los usuarios que  tienen abierto el directorio padre.
            # Que son los usuarios candidatos a desencadenar el evento
            $EventUsuarioABloquear = Get-NetOpenFiles | Where-Object {$_.FilePath -eq $PadreFicheroCambiado} | ForEach-Object { $_.user}
            # Buscamos los usuarios que tiene abierto el directorio padre.
            # Recuperamos el nombre del fichero log.
            $EventFicheroLog = (Get-RansomWareRule | where-object { $_.regla -eq $EventRegla}).FicheroLog
            # Por cada uno de los usuario localizados, bloqueamos su cuenta.
            # Cerramos las sesiones de red y guardamos un registro en el log.
            foreach ($item in $EventUsuarioABloquear)
            {
                #Averiguamos los usuarios que ha podido eliminar el fichero o directorio 
                $EventSesionesABloquear  = (Get-SmbSession | where {$_.ClientUserName -eq ($env:COMPUTERNAME +"\" +  $item)}).SessionId
                    
                # Obtenemos las direcciones IP desde donde el usuario desencadena el evento
                $EventSesionesABloquearIP = (Get-SmbSession | where {$_.ClientUserName -eq ($env:COMPUTERNAME +"\" +  $item)}).ClientComputerName
    
                # Bloqueamos los usuarios
                $pape = Lock-AccountUserName  $item

                # Cerramos las sesiones abiertas por cada uno de los usuarios
                $EventSesionesABloquear | ForEach-Object {Close-SmbSession  $_ -Force -Confirm:$false}
                    
                # Sólo en el caso de que especifiquemos un fichero log
                # Componemos la línea que vamos a escribir en el fichero log
                # y escribimos en el 
                if ($EventFicheroLog -ne ""){
                    $linea =  "$EventHora | Regla: $EventRegla | Cambiado:  $EventFicheroCambiado | Usuarios a bloquear: $item | Sessiones remotas: $EventSesionesABloquear | Equipos remotos: $EventSesionesABloquearIP "
                    Out-File -FilePath $EventFicheroLog -Append -InputObject $linea
                }
            }
        } # fin de BloqueEjecucionChanged


        # Se corresponde con el bloque de ejecución que va a ejecutarse cuando se
        # detecte un evento de cambio de nombre.
        $BloqueEjecucionRenamed= {

            # Obtenemos la hora en la que se genera el evento
            $EventHora = $Event.TimeGenerated
            # Obtenemos el nombre de la regla RansomWare
            $EventRegla =$Event.SourceIdentifier
            # Obtenemos el nombre completo del fichero o directorio que desencadena el evento
            $EventFicheroRenombrado = $Event.SourceArgs.FullPath
            # Averiguamos el padre del fichero o diretorio que desencadena el evento
            $PadreFicheroRenombrado = $EventFicheroRenombrado.Substring(0, $EventFicheroRenombrado.LastIndexOf("\") )
            # Recuperamos los usuarios que  tienen abierto el directorio padre.
            # Que son los usuarios candidatos a desencadenar el evento
            $EventUsuarioABloquear = Get-NetOpenFiles | Where-Object {$_.FilePath -eq $PadreFicheroRenombrado} | ForEach-Object { $_.user}
            # Buscamos los usuarios que tiene abierto el directorio padre
            # Recuperamos el nombre del fichero log
            $EventFicheroLog = (Get-RansomWareRule | where-object { $_.regla -eq $EventRegla}).FicheroLog
            # Por cada uno de los usuario localizados, bloqueamos su cuenta.
            # Cerramos las sesiones de red y guardamos un registro en el log.
            foreach ($item in $EventUsuarioABloquear)
            {
                #Averiguamos los usuarios que ha podido eliminar el fichero o directorio 
                $EventSesionesABloquear  = (Get-SmbSession | where {$_.ClientUserName -eq ($env:COMPUTERNAME +"\" +  $item)}).SessionId
    
                # Obtenemos las direcciones IP desde donde el usuario desencadena el evento
                $EventSesionesABloquearIP = (Get-SmbSession | where {$_.ClientUserName -eq ($env:COMPUTERNAME +"\" +  $item)}).ClientComputerName
    
                # Bloqueamos los usuarios
                $pape = Lock-AccountUserName  $item
    
                # Cerramos las sesiones abiertas por cada uno de los usuarios
                $EventSesionesABloquear | ForEach-Object {Close-SmbSession  $_ -Force -Confirm:$false}
                        
                # Sólo en el caso de que especifiquemos un fichero log
                # Componemos la línea que vamos a escribir en el fichero log
                # y escribimos en el 
                if ($EventFicheroLog -ne ""){
                    $linea =  "$EventHora | Regla: $EventRegla | Renombrado:  $EventFicheroRenombrado | Usuarios a bloquear: $item | Sessiones remotas: $EventSesionesABloquear | Equipos remotos: $EventSesionesABloquearIP "
                    Out-File -FilePath $EventFicheroLog -Append -InputObject $linea
                }
            }
        } # fin de BloqueEjecucionRenamed
    } #begin

    Process
    {


        # A continuación creamos el objeto capturador de eventos del sistema de ficheros.
        # Primero construimos la cadena de inicialización. 
        # Esta cadena indica si se obtentran eventos de los subdirectorios y 
        # qué propiedades del objeto desencadenan el evento.
        $CadenaInicializacion = @{IncludeSubdirectories = $Subdirectories;NotifyFilter = [IO.NotifyFilters]'Attributes , CreationTime , DirectoryName , FileName , LastAccess , LastWrite , Security , Size'}

        $CapturadorEventos= New-Object IO.FileSystemWatcher $PathDirectory,  $Filter  -Property $CadenaInicializacion

    

    
        # A continuación creamos una tarea para tratar a cada uno de los eventos
    
        # Tarea para tratar el evento de creación de objetos
        if ($Created)
        {     
            $RuleName =   "Created_"+ $PathDirectory + "\" + $Filter
            # En el caso de que la regla exista abortamos el comando. 
            if ((Test-RansomWareRuleName $RuleName )) 
            {
                Write-Host "La regla ya existe. No se ha podido crear: $RuleName" -ForegroundColor Yellow
                return 
            }        

            Register-ObjectEvent -InputObject  $CapturadorEventos -EventName Created -SourceIdentifier $RuleName -Action $BloqueEjecucionCreated
     
            # Guardamos el evento en la lista global de eventos para poder tratarlos
            # posteriormente.
    
            $Regla = New-Object PSObject
            $Regla  | Add-Member Regla $RuleName
            $Regla  | Add-Member CadenaInicializacion $CadenaInicializacion
            $Regla  | Add-Member FicheroLog $FileLog
            
            
            if ($Global:ReglasRansomWare -eq $null){ $Global:ReglasRansomWare = @() } 
            
            $Global:ReglasRansomWare = $Global:ReglasRansomWare +  $Regla

        }# if ($Created)

        

        # Tarea para tratar el evento de eliminación de objetos
        if ($Deleted)
        {     
            $RuleName = "Deleted_"+ $PathDirectory + "\" + $Filter
            # En el caso de que la regla exista abortamos el comando. 
            if ((Test-RansomWareRuleName $RuleName )) 
            {
                Write-Host "La regla ya existe. No se ha podido crear: $RuleName" -ForegroundColor Yellow
                return 
            }        
            
            Register-ObjectEvent -InputObject  $CapturadorEventos -EventName Deleted -SourceIdentifier $RuleName -Action $BloqueEjecucionDeleted
       
            # Guardamos el evento en la lista global de eventos para poder tratarlos
            # posteriormente.
    
            $Regla = New-Object PSObject
            $Regla  | Add-Member Regla $RuleName
            $Regla  | Add-Member CadenaInicializacion $CadenaInicializacion
            $Regla  | Add-Member FicheroLog $FileLog
            
            if ($Global:ReglasRansomWare -eq $null){ $Global:ReglasRansomWare = @() } 
            
            $Global:ReglasRansomWare = $Global:ReglasRansomWare +  $Regla
    
        }# if ($Deleted)

    
        # Tarea para tratar el evento de modificación de objetos
        if ($Changed)
        {     
            $RuleName =   "Changed_"+ $PathDirectory + "\" + $Filter
            # En el caso de que la regla exista abortamos el comando. 
            if ((Test-RansomWareRuleName $RuleName )) {
                Write-Host "La regla ya existe. No se ha podido crear: $RuleName" -ForegroundColor Yellow
                return 
            }        
            
            Register-ObjectEvent -InputObject  $CapturadorEventos -EventName Changed -SourceIdentifier $RuleName -Action $BloqueEjecucionChanged
       
            # Guardamos el evento en la lista global de eventos para poder tratarlos
            # posteriormente.
    
            $Regla = New-Object PSObject
            $Regla  | Add-Member Regla $RuleName
            $Regla  | Add-Member CadenaInicializacion $CadenaInicializacion
            $Regla  | Add-Member FicheroLog $FileLog
            
            if ($Global:ReglasRansomWare -eq $null){ $Global:ReglasRansomWare = @() } 
            
            $Global:ReglasRansomWare = $Global:ReglasRansomWare +  $Regla
        } # if ($Changed)



        # Tarea para tratar el evento de cambio de nombre de objetos
        if ($Renamed)
        {     
            $RuleName =   "Renamed_"+ $PathDirectory + "\" + $Filter
            # En el caso de que la regla exista abortamos el comando. 
            if ((Test-RansomWareRuleName $RuleName )) {
                Write-Host "La regla ya existe. No se ha podido crear: $RuleName" -ForegroundColor Yellow
                return 
            }        
            
            Register-ObjectEvent -InputObject  $CapturadorEventos -EventName Renamed -SourceIdentifier $RuleName -Action $BloqueEjecucionRenamed
       
            # Guardamos el evento en la lista global de eventos para poder tratarlos
            # posteriormente.
    
            $Regla = New-Object PSObject
            $Regla  | Add-Member Regla $RuleName
            $Regla  | Add-Member CadenaInicializacion $CadenaInicializacion
            $Regla  | Add-Member FicheroLog $FileLog
            
            if ($Global:ReglasRansomWare -eq $null){ $Global:ReglasRansomWare = @() } 
            
            $Global:ReglasRansomWare = $Global:ReglasRansomWare +  $Regla
        }
    
    }# Process

}







<#
.Synopsis
   Elimina una regla de protección RansomWare. 

.DESCRIPTION
   Elimina una regla de protección RansomWare. Es necesario que se proporcione
   el nombre de una regla.

.EXAMPLE    
        Remove-RansomWareRule -RuleName (Get-RansomWareRule)[0].Regla

        Elimina la primera regla RansomWare creada.
.EXAMPLE
         Get-RansomWareRule | where-object {Remove-RansomWareRule -Rule $_.Regla}

        Elimina todas reglas RansomWare creadas.



#>
function Remove-RansomWareRule

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Nombre de la regla RansomWare a eliminar.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-RansomWareRuleName $_){$true}else{Throw "No se encuentra la regla RansomWare: $_"}})]        
        [string]$RuleName
    )

    # Si la regla pasada como parámetro existe
    # La eliminamos de la tabla de reglas $Global:ReglasRansomWare
    $Global:ReglasRansomWare = $Global:ReglasRansomWare | Where-Object { $_.Regla -ne $RuleName}

    
    # Eliminamos la tarea de tratamiento de eventos
    Unregister-Event $RuleName
    
    

}




<#
.Synopsis
   Lista las reglas de protección RansomWare. 

.DESCRIPTION
   Lista las reglas de protección RansomWare.
        
.EXAMPLE
    Get-RansomWareRule

    El ejemplo lista todas las reglas de protección RansomWare. 
    

.EXAMPLE
    $directorio = "c:\\prueba"
    Get-RansomWareRule | Where-Object {$_.regla -match $directorio }

    
    
    
    El ejemplo lista todas las reglas de protección ante RansomWare,
    creadas para el directorio "c:\pruebas"
    




#>
function Get-RansomWareRule

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

    )

    $Global:ReglasRansomWare 

}











# -------------------- Apartado de red ------------------------- 
# Este apartado comprende los recursos para poder trabajar con 
# la red.
#
#
#  En concreto nos hemos centrado en la capacidad de detectar y
# repeler los ataques Man in The Middle. Para ello se han 
# implementado funciones para recuperar el contenido de la 
# tabla ARP y analizarlo, para ver si a lo largo del tiempo
# se produce un posible ataque.
#  También se proveen los mecanismos necesarios para
# bloquear a un atacante, haciendo uso de un sistema de 
# gestión de reglas que nos permiten bloquear o desbloquear
# una máquina en la red.
# 
#  Igualmente se ha implementado una función para poder 
# recuperar el nombre de los fabricantes de una determinada
# dirección MAC de un dispositivo de red.
#
#  A continuación se listan las funciones que desempeñan los 
# comandos implementados:
#
#   *  Listar tabla ARP del equipo local.
#   *  Listar los fabricantes de interfaces de red y el rango de direcciones MAC.
#   *  Recuperar el fabricante de un rango de dirección MAC.
#   *  Recuperar el rango de direcciones MAC de un fabricante.
#   *  Comprobar si hay ataque Man In The Middle.
#   *  Crear una regla de protección contra Man In The Middle.
#   *  Eliminar una regla de protección contra Man In The Middle.
#   *  Recupear una regla de protección contra Man In The Middle.
#   *  Comprobar si existe una regla de protección contra Man In The Middle.
#   *  Listar tabla ARP del equipo local.
#-----------------------------------------------------------
#
#
#
#
#






<#     
.SYNOPSIS     
    Devuelve la tabla ARP de la máquina actual.   
.DESCRIPTION   
    Devuelve la tabla ARP de la máquina actual, un array con el siguiente tipo de datos:   

   TypeName: Selected.System.String

Name        MemberType   Definition                         
----        ----------   ----------                         
Equals      Method       bool Equals(System.Object obj)     
GetHashCode Method       int GetHashCode()                  
GetType     Method       type GetType()                     
ToString    Method       string ToString()                  
IP          NoteProperty System.String IP=    
MAC         NoteProperty System.String MAC=




                  

.EXAMPLE    
    Get-ArpTable 
    Devuelve la tabla ARP de la máquina actual.



#>    
function Get-ArpTable{



[cmdletbinding(
    ConfirmImpact= 'low'
)]  


   $TablaArp =arp -a | where { $_ -match "[a-f0-9][a-f0-9]-" } | ForEach-Object {$_.trim()} | ForEach-Object {$_.substring(0,$_.LastIndexOf(" "))} |ForEach-Object {$_.trim()} | ForEach-Object{$_.Replace( $_.Substring($_.IndexOf(" ") , $_.LastIndexOf(" ") - $_.IndexOf(" ") +1)  ," ")} | select @{Name="IP";Expression={$_.substring(0,$_.IndexOf(" ")) }},@{Name="MAC";Expression={$_.Substring($_.IndexOf(" ")+1, $_.Length - $_.IndexOf(" ")-1)}} -Unique

    # Eliminamos los elementos usados como broadcast
    $TablaArp = $TablaArp | where mac -ne "ff-ff-ff-ff-ff-ff"
    $TablaArp
}




<#     
.SYNOPSIS     
    Esta función permite detectar un ataque "Man in the middle".
    Para lo cual compara el contenido actual de la tabla ARP y
    otra tabla pasada como parámetro.
    
    Devuelve el par IP-MAC de la máquina que está realizando el ataque.   
     
.DESCRIPTION   
    El parámetro de entrada es un array con el formato que sigue:   

   TypeName: Selected.System.String

Name        MemberType   Definition                         
----        ----------   ----------                         
Equals      Method       bool Equals(System.Object obj)     
GetHashCode Method       int GetHashCode()                  
GetType     Method       type GetType()                     
ToString    Method       string ToString()                  
IP          NoteProperty System.String IP="dirección IP"     
MAC         NoteProperty System.String MAC="dirección MAC"


    La salida es un array de los objetos con el formato siguiente:

 TypeName: Selected.System.Object

Name        MemberType   Definition                             
----        ----------   ----------                             
Equals      Method       bool Equals(System.Object obj)         
GetHashCode Method       int GetHashCode()                      
GetType     Method       type GetType()                         
ToString    Method       string ToString()                      
IpAtacante  NoteProperty System.String IpAtacante=  
IpVictima   NoteProperty System.String IpVictima=
MAC         NoteProperty System.String MAC=    
                  

.NOTES     
    Nombre:  Get-MITM   
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-MITM $TablaArp
    En el caso de encontrar un ataque, devuelve
    el par IP-MAC desde dónde se está realizando.
            
#>    
function Get-MITM
{



[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [array]$ArpTable                                  
        ) 



    # como valor de referencia usamos la tabla ARP pasada como parámetro $ArpTable 
    # Extraemos el contenido de la tabla ARP actual por medio del sigiente comando
    #$TablaArpNow = Get-ArpTable
    
    # elemento de prueba de la función main...
    
    #$TablaArpNow[0].MAC='58-23-8c-54-91-b3'
    #$TablaArpNow[0].IP='10.54.34.217'
    



    #Unimos el contenido de las dos tablas ARP
    #$TablaFin = $TablaArpNow + $ArpTable 
    #$ListaMAC = $TablaArpNow | select mac -Unique 


    
    #Si el número de pares IP-MAC es diferente del número de MAC diferentes existen dos equipos con la misma MAC, 
    #if ($ListaMAC.count -eq $TablaArpNow.Count)
    #{Write-Host "Existe un ataque man in the middle"
    #$ListaMAC
    #}
    #$false



    #$ArpTable    = Get-ArpTable
    $ArpTableNow = Get-ArpTable
    
    # elemento de prueba de la función main...
     

  # $ArpTableNow[1].MAC=$ArpTableNow[0].MAC
  # $ArpTableNow[2].MAC=$ArpTableNow[3].MAC
    
    #$ArpTable 

   #  $ArpTableNow


    #Unimos el contenido de las dos tablas ARP y recuperamos los pares IP,MAC únicos
    $TablaFin = $ArpTableNow  + $ArpTable | select IP,MAC -Unique 
    
    # seleccionamos las MAC que tengan más de una IP
    $TablaGroup = $TablaFin | Group-Object mac | select @{name="MAC"; Expression={$_.name}},@{name="cuantos"; Expression={$_.count}}  | where {$_.cuantos -gt 1}
    # $TablaGroup
    [int]$numataques=$TablaGroup.length
    $iniciado = $false
    #Recorremos las diferentes agrupaccones de MAC

    if ($numataques -eq 0){
        $macsuplantada = $TablaGroup.MAC
        $ipvictima= $ArpTable | where mac -eq $macsuplantada | select ip
        $ipatacante=$ArpTableNow |  where mac -eq $macsuplantada |  where  IP -ne $ipvictima.IP | select ip
         
        $ListaAtaque = New-Object -TypeName object | Select-Object MAC,IpVictima, IpAtacante
        $ListaAtaque.MAC=$macsuplantada
        $ListaAtaque.IpVictima=$ipvictima.IP
        $ListaAtaque.IpAtacante= $ipatacante.IP
    }
    else{
        
        do {

        $numataques--
        $macsuplantada = $TablaGroup[$numataques].MAC

        $ipvictima= $ArpTable | where mac -eq $macsuplantada | select ip
        $ipatacante=$ArpTableNow |  where mac -eq $macsuplantada |  where  IP -ne $ipvictima.IP | select ip
        
        $ListaAtaques = New-Object -TypeName object | Select-Object MAC,IpVictima, IpAtacante
        $ListaAtaques.MAC=$macsuplantada
        $ListaAtaques.IpVictima=$ipvictima.IP
        $ListaAtaques.IpAtacante= $ipatacante.IP
       
        
        if ($iniciado -eq $false){
            $ListaAtaque=$ListaAtaques 
            $iniciado= $true 
        }else{ $ListaAtaque = $ListaAtaque, $ListaAtaques} 

        } while($numataques -ne 0)
    }
    $ListaAtaque
}




<#     
.SYNOPSIS     
    Esta función muestra las reglas en el 
    cortafuegos, creadas con la función 
    New-MITMRuleFirewall. 
     
.DESCRIPTION   
    No tiene parámetros de entrada
 

.NOTES     
    Nombre: Get-MITMRuleFirewall 
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-MITMRuleFirewall
    Muestra las reglas en el Firewall,
    pertenecientes al grupo "MITM"



#>    
function Get-MITMRuleFirewall
{


[cmdletbinding(
    ConfirmImpact= 'low'
)]  

        
    $Existe= Get-NetFirewallRule  | Where-Object {$_.DisplayGroup -eq "MITM"}
    
    $Existe
}





<#     
.SYNOPSIS     
    Esta función comprueba si existe una regla en el 
    cortafuegos creada por la función 
    New-MITMRuleFirewall. 
     
.DESCRIPTION   
    El parámetro de entrada es el nombre de la regla
    con el formato "MITM-In-" + DirecciónIP
 

.NOTES     
    Nombre: Test-MITMRule 
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Test-MITMRule "MITM-In-192.168.53.2"
    Si encuentra la regla devuelve $True, en caso 
    contrario devuelve $False


             
#>    
function Test-MITMRule
{


[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.String]$RuleName                                  
        ) 
        
    $Existe = Get-NetFirewallRule  | Where-Object {$_.DisplayName -eq $RuleName}
    
    if ($Existe -eq $null){$false} 
    else {$True}    
}





<#     
.SYNOPSIS     
    Esta función crea una regla en el cortafuegos para bloquear
    una IP, tanto en el flujo de entrada como en el flujo de
    salida. Si ya está bloqueada no hace nada.
    
    El nombre de las reglas creadas es la concatenación de: 
    "MITM-In" + "IP A BLOQUEAR"   para flujo de entrada,
    "MITM-Out" + "IP A BLOQUEAR"   para flujo de salida
     
.DESCRIPTION   
    El parámetro de entrada es del tipo de dato
    System.Net.IPAddress.
 

.NOTES     
    Nombre: New-MITMRuleFirewall  
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    New-MITMRuleFirewall [IPAddress]"192.168.53.2"
    Si no está bloqueada, crea las reglas en el 
    cortafuegos:
    "MITM-In-192.168.53.2"
    "MITM-Out-192.168.53.2"


#>    
function New-MITMRuleFirewall
{



[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.Net.IPAddress]$IpAddress                                  
        ) 

    # creamos el nombre de las reglas
    $RuleNameIn= "MITM-In-"  + $IpAddress.ToString()
    $RuleNameOut="MITM-Out-" + $IpAddress.ToString()

    
    if (-not (Test-MITMRule $RuleNameIn)){
        $Papelera=New-NetFirewallRule -DisplayName $RuleNameIn  -Action Block -Direction Inbound  -Enabled True -InterfaceType Any -Profile Any -RemoteAddress $IpAddress -Group "MITM"
        $Papelera=New-NetFirewallRule -DisplayName $RuleNameOut -Action Block -Direction Outbound -Enabled True -InterfaceType Any -Profile Any -RemoteAddress $IpAddress -Group "MITM"
    }
}







<#     
.SYNOPSIS     
    Esta función elimina la regla del cortafuegos que 
    boquea una IP, dentro del grupo MITM. 

.DESCRIPTION   
    Esta función elimina la regla del cortafuegos que 
    boquea una IP, dentro del grupo MITM. 
    Si no existe no hace nada.
    
    El nombre de las reglas eliminadas es la concatenación de 
    "MITM-In" + "IP A BLOQUEAR"   para flujo de entrada
    "MITM-Out" + "IP A BLOQUEAR"   para flujo de salida
     


.NOTES     
    Nombre:  Remove-MITMRuleFirewall
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Remove-MITMRuleFirewall [IPAddress]"192.168.53.2"
    Elimina la regla que bloquea la IP, si existe.
    "MITM-In-192.168.53.2"
    "MITM-Out-192.168.53.2"

.EXAMPLE    
    Remove-MITMRuleFirewall -RemoveAll
    Elimina todas las reglas del grupo MITM
 



#>    
function Remove-MITMRuleFirewall
{



[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
        #  Es la dirección IP que queremos desbloquear del cortafuegos.
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.Net.IPAddress]$IpAddress,
        [Parameter(  
        # Esta opción nos indica si se van a desbloquear todas las reglas del cortafuegos, del grupo MITM"
            Position = 1,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [switch]$RemoveAll
      ) 

    
    if ($RemoveAll -eq $false){

        # creamos el nombre de las reglas
        $RuleNameIn= "MITM-In-"  + $IpAddress.ToString()
        $RuleNameOut="MITM-Out-" + $IpAddress.ToString()

    
        if (Test-MITMRule $RuleNameIn){
            $Papelera=Remove-NetFirewallRule -DisplayName $RuleNameIn
            $Papelera=Remove-NetFirewallRule -DisplayName $RuleNameOut
        }
    } else{
        Get-MITMRuleFirewall | Remove-NetFirewallRule
    }

}




<#     
.SYNOPSIS     
    Devuelve una tabla con el nombre de los fabricantes de red y los seis
    primeros caracteres de la MAC.  
     
.DESCRIPTION   
    Devuelve una tabla con el nombre de los fabricantes de red y los seis
    primeros caracteres de la MAC. Se necesita acceso a Internet para poder 
    recuperar la lista actualizada. Los datos devueltos tienen en siguiente 
    formato:   
      


   TypeName: Selected.System.String

Name        MemberType   Definition                        
----        ----------   ----------                        
Equals      Method       bool Equals(System.Object obj)    
GetHashCode Method       int GetHashCode()                 
GetType     Method       type GetType()                    
ToString    Method       string ToString()                 
MAC         NoteProperty System.String MAC=         
Provider    NoteProperty System.String Provider=

                  
.NOTES     
    Nombre:  Get-ListNetworkProviders  
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-NetworkProviders
    Devuelve una tabla con el nombre de los fabricantes de red y los seis
    primeros caracteres de la MAC.  
     



#>    
function Get-ListNetworkProviders{




[cmdletbinding(
    ConfirmImpact= 'low'
)]  



$web = New-Object System.Net.WebClient
$web.DownloadFile("http://www.cavebear.com/archive/cavebear/Ethernet/Ethernet.txt",$env:TEMP + "\Ethernet.txt")
$Net

$NetProvider = cat ($env:TEMP+"\Ethernet.txt") | where { $_ -match "^[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]"}
$NetProvider = $NetProvider | select @{Name="MAC";Expression={$_.Substring(0,6)}}, @{Name="Provider";Expression={$_.Substring(7,$_.Length-7) }}
$NetProvider
}






<#     
.SYNOPSIS     
    Devuelve los seis caracteres de la MAC del nombre de un 
    Fabricantes de adaptador de red, que se pasa como parámetro.  
     
.DESCRIPTION   
    Devuelve los seis caracteres de la MAC del nombre de un 
    Fabricantes de adaptador de red.  
    Como parámetro recibe el nombre del fabricante (cadena de texto).

   
                  
.NOTES     
    Nombre:  Get-NetworkProviderMAC  
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-NetworkProviderMAC "Wyse"
    Devuelve la tabla Fabricante-MAC de los fabricantes cuyo
    nombre contiene la cadena "Wyse".



#>    
function Get-NetworkProviderMAC{



[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  

     # Indica el nombre del fabricante del adaptador de red o parte de él.
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.String]$NameProvider
        ) 

    
    (Get-ListNetworkProviders | where provider -Match $NameProvider).mac
}




<#     
.SYNOPSIS     
    Devuelve el nombre del Fabricante de un adaptador de red.
     
.DESCRIPTION   
    Devuelve el nombre del Fabricante de adaptador de red. Acepta  
    como parámetro una cadena de caracteres, de los primeros seis 
    caracteres de la MAC.

                  
.NOTES     
    Nombre:  Get-NetworkProviderMAC  
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-NetworkProviderName  "E20C0F"
    Devuelve el nombre del fabricante de adaptadores de red 
    cuyos seis primeros caracteres de la MAC coinciden 
    con "E20C0F".



#>    
function Get-NetworkProviderName{



[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  

        # Indica los seis primeros caracteres del adaptador de red.
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.String]$MacProvider
        ) 

    
    (Get-ListNetworkProviders | where mac -Match $MacProvider).provider
}




# ------------------------- Almacenamiento ------------------------- 
# Este apartado comprende los recursos para trabajar con el sistema 
# de almacenamiento:
#  
#  Dentro de este apartado se han definido dos apartados más:
#
#        - Trabajar con Almacenes de correo Outlook (Ficheros .PST) 
#        - Listado y eliminación de ficheros temporales 
#
#-----------------------------------------------------------





#        - Trabajar con Almacenes de correo Outlook (Ficheros .PST) 
#
#  Este apartado provee los comandos y las estructuras de 
# datos necesarias para poder trabajar con ficheros de 
# almacenamiento de correos electrónicos de Microsoft Outlook 
# que tienen extensión .PST
#
#  Por medio de este desarrollo se permite abrir y cerrar ficheros
# .PST, comprobar si están abiertos, recorrer cada uno de sus 
# elementos (tanto bandejas de correos, como contactos, agenda,
# subscripciones, etc.).
#
#
#--------------------------------------------------------------


<#
.Synopsis
   Abre un fichero PST para poder trabajar con él.
.DESCRIPTION
   Abre un fichero PST para poder trabajar con él.
   En el caso de que ya esté abierto, no hace nada.

.EXAMPLE
   $a = Open-PSTFile myfilepst.pst
   Abre el fichero "myfilepst.pst" para trabajar con él.
   En $a almacena la ruta absoluta del fichero myfilepst.pst


.EXAMPLE
    (ls $env:LOCALAPPDATA\Microsoft\Outlook\*.pst).FullName  | Where-Object{open-PSTFile $_ } 
   Abre todos los ficheros PST contenidos en el directorio,
   donde se almacenan los ficheros PST del usuario actual (por defecto).
#>
function Open-PSTFile
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST que queremos abrir.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST
    )

    # Abrimos el entorno de Microsoft Outlook que nos 
    # permite trabajar con los almacenes de datos .PST

#    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
    $outlook = new-object -comobject outlook.application 
    $namespace = $outlook.GetNameSpace("MAPI")
     
    # No es necesario comprobar si el fichero .PST Ya está cargado, ya que 
    # si estaba cargado no se vuelve a cargar de nuevo.

    $a= $namespace.AddStore($pathfilePST)

    for ($i = 1; $i -le ($namespace.Folders.count); $i++)
    { 
        if ($namespace.Folders.Item($i).Store.FilePath -eq $pathfilePST){ return $namespace.Folders.Item($i).Store.FilePath} 
    }    
    

}









<#
.Synopsis
   Comprueba si un fichero PST está abierto.
.DESCRIPTION
   Comprueba si un fichero PST está abierto.
   Devuelve <boolean> 
   $True  - si se encuentra abierto
   $False - si no se encuentra abiert
.EXAMPLE
   Test-PSTFileOpen myfilepst.pst
   Comprueba si el fichero "myfilepst.pst" se encuentra abierto.
    
.EXAMPLE
   ls  'c:\midirectorio\*.pst'  | select  @{Name="Abierto"; Expression = {Test-PSTFileOpen $_.FullName}},@{Name="Fichero .PST"; Expression = {$_.FullName}} | ft -AutoSize
   El siguiente ejemplo comprueba cuales de los ficheros 
   PST del directorio "c:\midirectorio", se encuentran abiertos.
    

#>

function Test-PSTFileOpen
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST que queremos comprobar si está abierto.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST
    )

    # Abrimos el entorno de Microsoft Outlook que nos 
    # permite trabajar con los almacenes de datos .PST

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
    $outlook = new-object -comobject outlook.application 
    $namespace = $outlook.GetNameSpace("MAPI")
     
    for ($i = 1; $i -le ($namespace.Folders.count); $i++)
    { 
        if ($namespace.Folders.Item($i).Store.FilePath -eq $pathfilePST){ return $true }
    }    
    return $false
}







<#
.Synopsis
   Devuelve la ruta del fichero .PST, del almacén por defecto.
.DESCRIPTION
   Devuelve la ruta del fichero .PST, del almacén por defecto.
.OUTPUTS
   Devuelve el siguiente objeto:

  TypeName: System.Management.Automation.PSCustomObject

Name        MemberType   Definition                                                                     
----        ----------   ----------                                                                     
Equals      Method       bool Equals(System.Object obj)                                                 
GetHashCode Method       int GetHashCode()                                                              
GetType     Method       type GetType()                                                                 
ToString    Method       string ToString()                                                              
DisplayName NoteProperty System.String DisplayName=                                              
FilePath    NoteProperty System.String FilePath=

.EXAMPLE
   Get-PSTFileDefault
   Devuelve la ruta del fichero .PST, del almacén por defecto.
    
#>

function Get-PSTFileDefault
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    ( 
    )

    # Abrimos el entorno de Microsoft Outlook que nos 
    # permite trabajar con los almacenes de datos .PST

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
    $outlook = new-object -comobject outlook.application 
    $namespace = $outlook.GetNameSpace("MAPI")
    

    return $namespace.DefaultStore.FilePath

}






<#
.Synopsis
   Devuelve la ruta de los ficheros .PST, que se encuentran abiertos.
.DESCRIPTION
   Devuelve la ruta de los ficheros .PST, que se encuentran abiertos.
.OUTPUTS
   Devuelve <String> 
.EXAMPLE
   Get-PSTOpenFiles
   Devuelve la ruta de los ficheros .PST, que se encuentran abiertos.
    
#>
function Get-PSTOpenFiles
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    ( 
    )

    

    # Abrimos el entorno de Microsoft Outlook que nos 
    # permite trabajar con los almacenes de datos .PST

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
    $outlook = new-object -comobject outlook.application 
    $namespace = $outlook.GetNameSpace("MAPI")
     
    # No es necesario comprobar si el fichero .PST Ya está cargado, ya que 
    # si estaba cargado no se vuelve a cargar de nuevo.

    $a=@()

    for ($i = 1; $i -le ($namespace.Folders.count); $i++)
    { 
        $obj = New-Object PSObject
        $obj | Add-Member DisplayName ($namespace.Folders.Item($i).Store.DisplayName)
        $obj | Add-Member FilePath ($namespace.Folders.Item($i).Store.FilePath)
        $a = $a + $obj
    }    
    return $a
}








<#
.Synopsis
   Cierra un fichero .PST para que no sea accesible desde el entorno de Microsoft Outlook.
   No se podrá cerrar el .PST asignado al perfil por defecto.
.DESCRIPTION
   Cierra un fichero .PST para que no sea accesible desde el entorno de Microsoft Outlook.
   No se podrá cerrar el .PST asignado al perfil por defecto.
.EXAMPLE
   Close_PSTFile myfilepst.pst
   En el ejemplo se cierra el fichero "myfilepst.pst"
   

.EXAMPLE
   ls $env:LOCALAPPDATA\Microsoft\Outlook\*.pst | Close-PSTFile
   En el ejemplo se cierran todos los ficheros .PST contenidos en el directorio
   por defecto de Outlook del usuario actual.
   Si el .PST no estaba abierto no hace nada.


.EXAMPLE
   Get-PSTOpenFiles | ForEach-Object { Close-PSTFile $_.FilePath}
   Cierra todos los ficheros PST abiertos.

#>

function Close-PSTFile
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST que queremos cerrar.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST
    )

    # Abrimos el entorno de Microsoft Outlook que nos 
    # permite trabajar con los almacenes de datos .PST

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
    $outlook = new-object -comobject outlook.application 
    $namespace = $outlook.GetNameSpace("MAPI")
     
    # No es necesario comprobar si el fichero .PST Ya está cargado, ya que 
    # si estaba cargado no se vuelve a cargar de nuevo.
    
    for ($i = 1; $i -le ($namespace.Folders.count); $i++)
    { 
        # cerramos el .PST siempre que sea diferente del almacen por defecto
        if ( ($namespace.Folders.Item($i).Store.FilePath -eq $pathfilePST) -and  ((Get-PSTFileDefault) -ne $pathfilePST))
        {
            $namespace.Folders.Item($i).Store.FilePath
            $namespace.RemoveStore( $namespace.Stores.Item($i).GetRootFolder())   
        }
    }    
}




# En este apartado se trabaja con los directorios de los PST
# y con los elementos que los contienen 
#
#
#
# Para listar los directorios contenidos en los PST se usa la
# la función Get-PSTListDirectory que a su vez se ayuda de su
# función anidada Get-PSTListDirectoryAux, ya que hacen uso
# de la recursividad para su funcionamiento.



<#
.Synopsis
   Lista los directorios contenidos en un fichero .PST.
.DESCRIPTION
   Lista los directorios contenidos en un fichero .PST.
   En esta lista se incluyen recuros como los contactos, 
   el calendario, Fuentes RSS, entre otras.
   El listado lo hace de manera recursiva. 

   Los objetos de la lista incluyen ruta de los directorios
   y el objeto COM correspondiente.
   

.EXAMPLE
   Get-PSTListDirectory myfilepst.pst
   El ejemplo lista los directorios del .PST myfilepst.pst


#>

function Get-PSTListDirectory
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST del que queremos listar los directorios.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST
    )

        <#
        .Synopsis
           Función recursiva usada para listar los directorios
           Sólo es accesible desde la función Get-PSTListDirectory.
        .DESCRIPTION
           Función recursiva usada para listar los directorios
           Sólo es accesible desde la función Get-PSTListDirectory.
        .EXAMPLE
           Get-PSTListDirectory $ObjRaizPST
           El siguiente ejemplo lista los directorios del un fichero .PST
           Para ello debnemos pasar como parámetro el objeto raiz del fichero
           .PST
           

        #>
        function Get-PSTListDirectoryAux
        {
            [CmdletBinding(ConfirmImpact='Medium')]
            Param
            (
                # Hace referencia al objeto que se obtiene
                # como resultado de recuperar un fichero PST
                # montado
                [psobject]$dir
            )

            # Si el directorio ya no tiene más subdirectorios la lista
            # vacía, que equivale a @()
            if ($dir.Folders.Count -eq 0){ return @() }
    
            # Iniciamos la lista vacía para poder hacer la
            # unión de la lista inicial recursiva y la generada
            # desde la raiz.
            $lista =  @()
            # Añadimos la entrada al listado de directorio
            for ($i = 1; $i -le ($dir.Folders.Count); $i++)
            { 
                # Creamos la entrada del listado de directorio
                $obj = New-Object PSObject
                $obj | Add-Member FolderPath ($dir.Folders.item($i).FolderPath)
                $obj | Add-Member Folder    ($dir.Folders.item($i))
                #lista recursiva de la carpeta $i
                $Listarec = Get-PSTListDirectoryAux $dir.Folders.Item($i) # $lista 
                # unimos a la lista del directori el siguiente directorio y todos sus hijos
                $lista = $lista  + $obj + $Listarec
            }
            # devolvemos la lista de directorios recursivos
            $lista        
        } # Fin de la función auxiliar Get-PSTListDirectoryAux



    # Abrimos el entorno de Microsoft Outlook que nos 
    # permite trabajar con los almacenes de datos .PST

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
    $outlook = new-object -comobject outlook.application 
    $namespace = $outlook.GetNameSpace("MAPI")
     
    # No es necesario comprobar si el fichero .PST Ya está cargado, ya que 
    # si estaba cargado no se vuelve a cargar de nuevo.
    
    $papelera = Open-PSTFile $pathfilePST
    
    # Entre todos los ficheros .PST abiertos cargamos el OBJETO correpsondiente
    # a la ruta pasada en el parámetro $pathfilePST
    for ($i = 1; $i -le ($namespace.Folders.count); $i++)
    { 
        # elegimos el PST cuya ruta coincida con la introducida como parámetro
        if ( ($namespace.Folders.Item($i).Store.FilePath -eq $pathfilePST))
        {
           $RootFolder = ($namespace.Folders.Item($i).Store).GetRootFolder()
           break
        }
    }    

    
    # Llamamos a la función auxiliar con el objeto
    # que representa la raíz del fichero .PST 
    Get-PSTListDirectoryAux $RootFolder

}





<#
.Synopsis
   Este comando abre un fichero PST y nos devuelve el contenido de 
   un directorio especificado.
.DESCRIPTION
   Este comando abre un fichero PST y nos devuelve el contenido de 
   un directorio especificado.
   Sólo del directorio actual. No lo hace de manera recursiva.
.EXAMPLE
   Get-PSTContentDirectory -pathfilePST (Get-PSTFileDefault) -pathDirectoryPST "\\Carpetas personales\Bandeja de entrada"
   Lista el contenido del  directorio "\\Carpetas personales\Bandeja de entrada" del PST por defecto.

.EXAMPLE
   $contactos = Get-PSTContentDirectory -pathfilePST (Get-PSTFileDefault) -pathDirectoryPST "\\Carpetas personales\Contactos"
   C:\PS>$contactos |  gm | ?{$_.MemberType -eq "Property"}
   
   Muestra las propiedades de un contacto del PST por defecto.

.EXAMPLE
   $propietario ="Juan Antonio Nieto"
   C:\PS>$Tareas = Get-PSTContentDirectory -pathfilePST (Get-PSTFileDefault) -pathDirectoryPST "\\Carpetas personales\Tareas"
   C:\PS>$Tareas  | ?{$_.Owner -eq $propietario}
   
   Muestra las tareas propiedad de "Juan Antonio Nieto" del PST por defecto.
   
#>

function Get-PSTContentDirectory
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST que queremos explorar.
        [Parameter(Mandatory=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST,

            # Ruta del directorio cuyos elementos queremos recuperar.
        [Parameter(Mandatory=$true)]
        [string]$pathDirectoryPST



    )

    # Primero obtenemos un listado de los directorios
    # que contiene el PST elegido como parámetro
    $Directorios = Get-PSTListDirectory $pathfilePST

    # Ahora de los directorios devueltos elegimos el que hemos pasado como parámetro
    # y del campo Folder mostramos todos los componentes con la propiedad items
    ($Directorios | ? {$_.FolderPath -eq $pathDirectoryPST}).Folder.items 


}














# -----Listado y Eliminado de temporales --------------
# Este apartado implementa las funciones que permiten
# el listado y eliminación de ficheros temporales tanto 
# propios del usuario como del sistema.
#
#
#
# 
#-------------------------------------------------------
















<#
.Synopsis
   Obtiene una lista de las cuentas de usuarios existentes en un PC.
   
.DESCRIPTION
   Obtiene una lista de las cuentas de usuarios existentes en un PC.
   Puede que esos usuarios no hayan iniciado sesión y
   que su directorio personal no exista o sea diferente del creado por defecto.
.EXAMPLE
   Get-UserList
   Obtiene una lista de las cuentas de usuarios.
.EXAMPLE
   Get-UserList | select  @{Name="Path"; Expression = {(($env:USERPROFILE.Substring(0,$env:USERPROFILE.LastIndexOf("\") +1)) + $_.user)}} | ft -AutoSize
   Calcula el directorio personal de cada usuario.


.EXAMPLE
   Get-UserList | select  @{Name="Existe"; Expression = {(Test-Path (($env:USERPROFILE.Substring(0,$env:USERPROFILE.LastIndexOf("\") +1)) + $_.user))}}, @{Name="Path"; Expression = {(($env:USERPROFILE.Substring(0,$env:USERPROFILE.LastIndexOf("\") +1)) + $_.user)}} | ft -AutoSize
   Calcula el directorio personal de cada usuario y dice si el directorio existe.
#>

function Get-UserList
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
    )

  $a=@()
   
  foreach ($item in (gwmi  Win32_UserAccount).name)
  {
    $obj = New-Object PSObject
    $obj | Add-Member User $item
    $a = $a + $obj
  }
  $a
}



<#
.Synopsis
   Lista el contenido de un directorio
.DESCRIPTION
   Lista el contenido de un directorio pasado como parámetro.
.EXAMPLE
   Get-DirectoryContent -pathfileordirectory "c:\tmp\poupelle".
   Lista el contenido del directorio "c:\tmp\poupelle". 
.EXAMPLE
   Get-DirectoryContent "c:\tmp\poupelle" |Get-FileHash -Algorithm SHA512 | Export-Csv -Delimiter ";" -LiteralPath $env:TEMP\lista-hash.csv 
   Crea un fichero .csv, que contiene los ficheros de la carpeta "c:\tmp\poupelle" con sus correspondientes hash (sha512).

#>
function Get-DirectoryContent
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
        # Directorio del que vamos a listar el contenido.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el directorio: $_"}})]        
        [string]$pathfileordirectory
    )
    Get-ChildItem $pathfileordirectory -Recurse -Force -ErrorAction SilentlyContinue
}













<#
.Synopsis
   Elimina el contenido de un directorio.
.DESCRIPTION
   Elimina el contenido de un directorio pasado como parámetro.
   Es necesario diferenciarlo del comando Remove-Item, que borra el directorio completo.
.EXAMPLE
   Remove-DirectoryContent -pathfileordirectory "c:\tmp\poupelle".
   Elimina el contenido del directorio "c:\tmp\poupelle". 
.EXAMPLE
   Remove-DirectoryContent -pathfileordirectory "c:\tmp\poupelle" -Credential $cred
   Elimina el contenido del directorio "c:\tmp\poupelle". 
   Usando las credenciales almacenadas en la variable $cred.
   Si la variable $cred no ha sido inicializada muestra una ventana contextual para inicializarla.
.EXAMPLE
   Remove-DirectoryContent -pathfileordirectory "c:\tmp\poupelle" -Credential (Get-Credential)
   Elimina el contenido del directorio "c:\tmp\poupelle". 
   Pide las credenciales por pantalla.

#>

function Remove-DirectoryContent
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
        # Directorio del que se va a eliminar el contenido.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el directorio: $_"}})]        
        [string]$pathfileordirectory,

        # Credenciales con las que se elimina el contenido del directorio.
        [Parameter()]
        [PSCredential]$Credential
    )
   
  if ($Credential){
    ls $pathfileordirectory -Recurse | rm -Credential $Credential -recurse -confirm:$false -ErrorAction SilentlyContinue
  } else{
    ls $pathfileordirectory -Recurse | rm  -recurse -confirm:$false -ErrorAction SilentlyContinue
  }


}






<#
.Synopsis
   Lista ficheros temporales.

.DESCRIPTION
   Lista los ficheros temporales especificados en los parámetros.

.EXAMPLE    
    Get-FileTemp -TempUser -Prefetch -TempWindows -InternetCache 
    Lista:
        - los ficheros temporales del usuario actual 
        - los ficheros Prefetch 
        - los ficheros temporales de Windows
        - los ficheros temporales de Internet Explorer
        
.EXAMPLE
    Get-FileTemp -Cookies -History -Recent
    Con este ejemplo se listan:
        - los ficheros de las cookies.
        - los ficheros del historial de navegación de Explorer e Internet Explorer.
        - los ficheros recientes.
.EXAMPLE
    Get-FileTemp -currentuser 
    Lista los ficheros temporales del usuario actual.

#>
function Get-FileTemp

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Lista el contenido del directorio Prefetch.
        [Parameter()]
        [switch]$Prefetch,

        # Lista el contenido del directorio temporal de Windows.
        [Parameter()]
        [switch]$TempWindows,

        # Lista los temporales del usuario actual.
        [Parameter()]
        [switch]$TempUser,

        # Lista las Cookies de Internet Explorer del usuario actual.
        [Parameter()]
        [switch]$Cookies,

        # Lista el historial de Internet Explorer del usuario actual.
        [Parameter()]
        [switch]$History,

        # Lista la caché de Internet Explorer del usuario actual.
        [Parameter()]
        [switch]$InternetCache,

        # Lista los ficheros recientes del usuario actual.
        [Parameter()]
        [switch]$Recent,

        # Lista los enlaces favoritos del usuario actual.
        [Parameter()]
        [switch]$Favorites
    )




    # Directorio prefetch de windows
    if ($Prefetch){
            Get-DirectoryContent ($env:windir + "\Prefetch") 
    }

    # Directorio temporal de windows
    if ($TempWindows){
            Get-DirectoryContent ($env:windir + "\Temp") 
    }

    # Directorio temporal del usuario actual
    if ($TempUser){
            Get-DirectoryContent $env:tmp  
    }


# Para acceso a las variables de directorios especiales se hace uso de las especificaciones
# que aparecen en el siguiente enlace 
# https://msdn.microsoft.com/es-es/library/system.environment.specialfolder(v=vs.110).aspx    
#
    # Directorio Cookies del usuario actual
    if ($Cookies){
            Get-DirectoryContent ([Environment]::GetFolderPath("Cookies"))
    }
    
    # Directorio del histórico de Internet
    if ($History){
            Get-DirectoryContent ([Environment]::GetFolderPath("History"))
    }

    # Directorio temporal de IE del usuario actual
    if ($InternetCache){
            Get-DirectoryContent ([Environment]::GetFolderPath("InternetCache"))
            Get-DirectoryContent ([Environment]::GetFolderPath("InternetCache") + "\IE") 
    }


    # Directorio de documentos abiertos recientemente
    if ($Recent){
            Get-DirectoryContent ([Environment]::GetFolderPath("Recent"))
    }


    # Directorio de favoritos del usuario actual
    if ($Favorites){
            Get-DirectoryContent ([Environment]::GetFolderPath("Favorites"))
    }

}










<#
.Synopsis
   Elimina ficheros temporales.

.DESCRIPTION
   Elimina los ficheros temporales especificados por parámetro.

.EXAMPLE    
    Remove-FileTemp -TempUser -Prefetch -TempWindows -InternetCache -Credential (Get-Credential)
    Usando las credenciales solicitadas por pantalla, elimina:
        - los ficheros temporales del usuario actual. 
        - los ficheros Prefetch.
        - los ficheros temporales de Windows.
        - los ficheros temporales de Internet Explorer.

        
.EXAMPLE
    Remove-FileTemp -Cookies -History -Recent
    Con este ejemplo se eliminan:
        - los ficheros de las cookies.
        - los ficheros del historial de navegación de Explorer e Internet Explorer.
        - los ficheros recientes.
.EXAMPLE
    Remove-FileTemp -TempUser 
    Elimina los ficheros temporales del usuario actual.

#>
function Remove-FileTemp

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Borra el contenido del directorio Prefetch.
        [Parameter()]
        [switch]$Prefetch,

        # Borra el contenido del directorio temporal de Windows.
        [Parameter()]
        [switch]$TempWindows,

        # Borra los temporales del usuario actual.
        [Parameter()]
        [switch]$TempUser,

        # Borra las Cookies de Internet Explorer del usuario actual.
        [Parameter()]
        [switch]$Cookies,

        # Borra el historial de Internet Explorer del usuario actual.
        [Parameter()]
        [switch]$History,

        # Borra la caché de Internet Explorer del usuario actual.
        [Parameter()]
        [switch]$InternetCache,

        # Borra los ficheros recientes del usuario actual.
        [Parameter()]
        [switch]$Recent,

        # Lista los enlaces favoritos del usuario actual.
        [Parameter()]
        [switch]$Favorites,

        # Credenciales para el comando.
        [Parameter()]
        [PSCredential]$Credential
    )




    # Directorio prefetch de windows
    if ($Prefetch){
        if ($Credential){
            Remove-DirectoryContent ($env:windir + "\Prefetch") -Credential $Credential 
        } else{
            Remove-DirectoryContent ($env:windir + "\Prefetch") 
        }
    }

    # Directorio temporal de windows
    if ($TempWindows){
        if ($Credential){
            Remove-DirectoryContent ($env:windir + "\Temp") -Credential $Credential 
        } else{
            Remove-DirectoryContent ($env:windir + "\Temp") 
        }
    }




    # Directorio temporal del usuario actual
    if ($TempUser){
        if ($Credential){
            Remove-DirectoryContent $env:tmp -Credential $Credential
        } else{
            Remove-DirectoryContent $env:tmp  
        }
    }


# Para acceso a las variables de directorios especiales se hace uso de las especificaciones
# que aparecen en el siguiente enlace 
# https://msdn.microsoft.com/es-es/library/system.environment.specialfolder(v=vs.110).aspx    
#
    # Directorio Cookies del usuario actual
    if ($Cookies){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("Cookies"))  -Credential $Credential
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("Cookies"))
        } 
    }
    
    # Directorio del histórico de Internet
    if ($History){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("History")) -Credential $Credential
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("History"))
        } 
    }

    # Directorio temporal de IE del usuario actual
    if ($InternetCache){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache")) -Credential $Credential
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache") + "\IE")  -Credential $Credential
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache"))
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache") + "\IE") 
        } 
    }


    # Directorio de documentos abiertos recientemente
    if ($Recent){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("Recent")) -Credential $Credential
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("Recent"))
        } 
    }

    # Directorio de favoritos del usuario actual
    if ($Favorites){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("Favorites")) -Credential $Credential
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("Favorites"))
        } 
    }
}










# ------------------- Registro de Windows ------------------ 
# Este apartado comprende los recursos para poder trabajar
# con el Registro de Windows:
#
#  A través de las últimas versiones de PowerShell se proveen
# herramientas que permiten recorrer el registro de 
# Windows, hacer inserciones, actualizaciones y eliminados.
#
#  Sin embargo no se han encontrado en PowerShell 
# herramientas para montar ficheros del registro de Windows 
# y que permita su gestión. Para ello se ha creado este
# apartado que provee de cuatro comandos y de la estructura
# de datos que permite la gestión de montado y desmontado 
# de tantos ficheros de registro de Windows como se desee.
#
# Los comandos que nos permiten operar son las siguientes:
# 
#    -Montar fichero de registro de Windows.
#    -Desmontar fichero de registro de Windows.
#    -Comprobar si un fichero ya está montado.
#    -Listar ficheros montados y sus características.
#
#
#
#
#
#
#
#-----------------------------------------------------------
#






<#
.Synopsis
    Obtiene información de los ficheros de registro de Windows montados. 


.DESCRIPTION
    Obtiene información de los ficheros de registro de Windows montados. 
    Acepta como parámetro la ruta de un fichero de registro de Windows.
.EXAMPLE    
    Get-RegWindowsFile

    Obtiene información de los ficheros de registro de Windows montados. 
        
.EXAMPLE    
    (Get-RegWindowsFile).PathFile

    Obtiene la ruta de los ficheros de registro de Windows montados. 

.EXAMPLE    
    (Get-RegWindowsFile c:\Users\juan\NTUSER.DAT).PSDriver.Name

    Obtiene el nombre de la unidad PSDrive en la que se encuentra 
    montada el fichero de registro de Windows 
    c:\Users\juan\NTUSER.DAT
        
#>
function Get-RegWindowsFile

{

    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Nombre del fichero de registro de Windows a desmontar.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$PathFile
    )

    
    # Devuelve la variable global en la que se almacena la 
    # información referente al fichero de registro de Windows.
    #
    # Cuando se especifica la ruta de un fichero de registro de 
    # Windows, se aplica el filtro correspondiente.
    if ($PathFile -eq "")
    {
        return ($Global:RegWindowsFile) 
    }

    return ($Global:RegWindowsFile| Where-Object {$_.PathFile -eq $PathFile}) 
    
    


}









<#
.Synopsis
    Comprueba si se ha montado un fichero de registro de Windows. 

.DESCRIPTION
    Comprueba si se ha montado un fichero de registro de Windows. 
    En el caso afirmativo devuelve $true.
    En caso negativo devuelve $false. 

.EXAMPLE    
    Test-RegWindowsFile c:\users\juan\NTUSER.DAT

    Comprueba si se ha montado el fichero de registro de Windows 
    correspondiente al usuario "juan".
        
#>
function Test-RegWindowsFile

{
   
    Param
    (

        # Nombre del fichero de registro de Windows a comprobar.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$PathFile
    )
   
    
    # En el caso de que en el array de entradas de ficheros
    # de registros de Windows existan coincidencias, con
    # la ruta pasada como parámetro, devolvemos $true.
    # En caso contrario devolvemos $false 

    if (Get-RegWindowsFile | Where-Object {$_.PathFile -eq $PathFile})
    {
        return $true
    }
    return $false

}











<#
.Synopsis
    Monta un fichero de registro de Windows pasado como parámetro. 

.DESCRIPTION
    Monta un fichero de registro de Windows pasado como parámetro  
    y crea la unidad PSDrive correspondiente para acceder a su 
    contenido.

.EXAMPLE    
    Mount-RegWindowsFile -PathFile "c:\registros\fichero.dat"

    Monta un fichero del registro de Windows "c:\registros\fichero.dat"
    y crea la unidad PSDriver correspondiente.
    Para ver la unidad PSDrive asignada a un ficheros usar el comando
    
    Get-RegWindowsFile 
    
.EXAMPLE    
    ls -File | foreach {Mount-RegWindowsFile $_.FullName}

    Monta todos los ficheros del registro de windows contenidos
    en el directorio actual y crea la unidad PSDriver correspondiente.
    Para ver la unidad PSDrive asignada a un ficheros usar el comando
    
    Get-RegWindowsFile 
    
        
#>
function Mount-RegWindowsFile

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Fichero de registro de Windows a montar.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero: $_"}})]        
        [string]$PathFile
    )
    
    # En el caso de que no se encuentre montado el registro de Windows 
    # HKEY_LOCAL_MACHINE lo montamos en la unidad hklm de PSDrive. 

    if (-not (Get-PSDrive | where {$_.Name -eq "hklm" }) ) 
    {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -Scope GLOBAL
    }



    # Comprobamos que el fichero de registro de Windows que queremos montar
    # no se encuentra ya montado.
    if (($Global:RegWindowsFile | Where-Object { $_.PathFile -eq $PathFile}) -ne $null){
        Throw "El fichero de registro ya fue montado:" 
    }


    # Para montar registro de Windows en un nuevo PSDrive.
    # Usamos nombres de unidades fijas todas empiezan con la
    # cadena "HKTmp" y a continuación se añade un número. 
    # Este número lo almacenamos en las entradas de la variable
    # $Global:RegWindowsFile en el campo "Num"
    # 
    # Por lo que los nombres de unidades tendrán el siguiente 
    # formato: HKTmp1, HKTmp2, HKTmp3, HKTmp4, HKTmp5, etc 
    # 
    # Estos mismos nombres son usados para montar el fichero 
    # de registro de Windows sobre el registro 
    # HKEY_LOCAL_MACHINE es decir que las claves correspondientes
    # a los nuevos ficheros de registro de Windows montados tendrían 
    # el siguiente formato:
    # HKLM\HKTmp1, HKLM\HKTmp2, HKLM\HKTmp3, etc.
    #
    # Calculamos el número del PSDrive del registro del fichero 
    # de registro de Windows que queremos insertar.
    # 

    if ($Global:RegWindowsFile -eq $null)
    {
        # Si aún no hemos montado ningún fichero,
        # el primer fichero a insertar es el 1, con
        # lo que:
        # clave: "HKLM\HKTmp1"
        # unidad PSDrive: "HKTmp1:"
        $num =1
    }
    else
    {
        # En el caso de que ya haya abierto un fichero de registro de Windows
        # calculamos el siguiente número. Para ello al mayor número de los
        # ficheros abiertos lo incrementamos en uno.
        $num = ($Global:RegWindowsFile | ForEach-Object {$_.Num} | Sort-Object -Descending)[0] +1
    }

    $basura = REG LOAD HKLM\HKTmp$num $PathFile  
    
    # Si el proceso de montaje del fichero de registro de Windows
    # da error, abortamos la ejecución del comando y salimos sin crear 
    # cambios en la variable global $Global:RegWindowsFile. No se    
    # monta el fichero de registro de Windows en la unidad calculada.
    $NuevaRuta = "HKLM:\HKTmp" + [string]$num
    
    # Detectamos error en el caso de que no podamos acceder
    # a la ruta que se crea 
    if (-not (Test-Path $NuevaRuta))
    {
        return
    }
    
    # El siguiente objeto es para añadir en el registro de ficheros
    # de registros de Windows la entrada correspondiente.
    # Importante especificar en el comando PSDrive el parámetro 
    # Scope con valor Global, para que al salir de la función 
    # tengamos acceso a la unidad creada.

    $obj = New-Object PSObject 
    $obj | Add-Member PSDriver (New-PSDrive -Name HKTmp$num -PSProvider Registry -Root HKLM\HKTmp$num -Scope global)
    $obj | Add-Member Num $num
    $obj | Add-Member PathFile $PathFile
    

    # Comprobamos si se ha creado correctamente 
    # la unidad PSDrive.
    # En caso contrario desmontamos la clave 
    # HKTmp$num de HKLM y abortamos el proceso.
    $NombreUnidad = "HKTmp" +[string]$num
    if (-not (Get-PSDrive | where {$_.name -eq $NombreUnidad }) )
    {
        $basura = REG UNLOAD HKLM\HKTmp$num  
        return
    }

    # Si es el primer fichero abierto es necesario
    # inicializar el array a vacío.
    if ($Global:RegWindowsFile -eq $null)
    {    
        # Iniciamos la estructura donde vamos a almacenar los ficheros 
        # de registro de Windows al conjunto vacío.
        $Global:RegWindowsFile = @()
    }
    
        
    # Añadimos la entrada al array de ficheros de registro de Windows abiertos.
    $Global:RegWindowsFile = $Global:RegWindowsFile + $obj


}



<#
.Synopsis
    Desmonta un fichero de registro de Windows cuya ruta es pasada
    como parámetro. 

.DESCRIPTION
    Desmonta un fichero de registro de Windows cuya ruta es pasada
    como parámetro y elimina la unidad PSDrive correspondiente, para 
    acceder a su contenido.

.EXAMPLE    
    Dismount-RegWindowsFile -PathFile C:\users\qq\NTUSER.DAT

    Desmonta el fichero de registro de Windows "C:\users\qq\NTUSER.DAT" 
    y elimina la unidad PSDrive correspondiente, para acceder a su 
    contenido.
.EXAMPLE    
    Get-RegWindowsFile| foreach {Dismount-RegWindowsFile $_.PathFile}

    Desmonta todos los ficheros de registro de Windows que se encuentran
    montados y elimina la unidad PSDrive correspondiente, para acceder a
    su contenido.
        



#>
function Dismount-RegWindowsFile

{

    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Nombre del fichero de registro de Windows a desmontar.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-RegWindowsFile $_){$true}else{Throw "El fichero de registro de Windows '$_' no se encuentra abierto."}})]        
        [string]$PathFile
    )


    # Obtenemos el nombre de la unidad PSDrive correspondiente 
    # al fichero de registro de Windows.
    $name = (Get-RegWindowsFile | Where-Object {$_.PathFile -eq $PathFile}).PSDriver.Name

    # A continuación desmontamos el fichero de registro de Windows.
    # El montaje de los ficheros de registro de Windows afecta
    # a tres estructuras y por lo tanto debemos realizar tres 
    # operaciones.
    # En el caso que alguna de las operaciones falle, tenemos que 
    # restaurar el estado inicial, de cada una de ellas
    # para evitar la inconsistencia de las estructuras implicadas.
    #
    # Los cambios los hacemos en tres pasos:
    
    #  - eliminamos la unidad PSDrive
    Get-PSDrive -Name $Name | Remove-PSDrive
    # si no se ha podido eliminar el PSDrive abortamos la operación.
    if ((Get-PSDrive | where {$_.name -eq $name}))
    {
      #  New-PSDrive -Name $name -PSProvider Registry -Root HKLM\$name -Scope global
      #  Throw "No se puede desmontar el fichero de registro de Windows, porque la unidad $name está en uso."
        return
    }

    #  - desmontamos el fichero
    $basura = REG UNLOAD HKLM\$name
    
    # Si no podemos desmontar el fichero de registro de Windows abortamos la operación
    # y creamos de nuevo el punto de montaje del PSDrive 
    if (Test-Path HKLM:\$name)
    {
        New-PSDrive -Name $name -PSProvider Registry -Root HKLM\$name -Scope global
        return
    }
    


    #  - lo reflejamos en la variable global $Global:RegWindowsFile
    $Global:RegWindowsFile = $Global:RegWindowsFile | Where-Object {$_.PSDriver.Name -ne $name}
    
    # En el caso de que sólo quede un elemento lo transforma de array a entrada, 
    # por lo que debemos convertirlo en array de nuevo. En caso contrario da 
    # problemas al añadir nuevas entradas.
    if ($Global:RegWindowsFile -ne $null)
    {
        if  ($Global:RegWindowsFile.count -eq $null) 
        {
            $Global:RegWindowsFile = @() +  $Global:RegWindowsFile
        } 
    }

}








# ----------- Memoria (procesos y servicios)---------------- 
# Este apartado comprende los recursos para poder trabajar 
# con la memoria y los servicios.
#
# Las principales funciones de este apartado son recopilar
# información de los procesos y los servicios en memoria.
# En todas las funciones implementadas en este apartado se
# obtienen las rutas en disco de los procesos, servicios y 
# ficheros en los que se apoyan.
# A través de estos ficheros se obtienen los hash. A través 
# de estos últimos se puede buscar en bases de conocimientos
# si estos elementos implican algún riesgo para nuestro 
# sistema.
# La legitimidad de los ficheros se puede verificar a través de 
# cualquiera de las API disponibles. Como ejemplo podemos 
# referenciar a las disponibles por Internet, una de ellas es 
# Virus Total, de la que ya existe una API para PowerShell. 
#-----------------------------------------------------------






<#
.Synopsis
   Obtiene una lista de todos los módulos usados por un proceso.
.DESCRIPTION
   Obtiene una lista de todos los módulos usados por un proceso.
   Y calcula  su SHA256
   Por defecto muestra sólo los módulos principales.
   Se pueden aplicar filtros por el Id y por el nombre de proceso.
.EXAMPLE
    Get-ProcessMolules -ProcessName notepad -AllModules
    
    Muestra todos los módulos del proceso con nombre "notepad".

.EXAMPLE
    Get-ProcessMolules -Id 1008 -AllModules
    
    Muestra todos los módulos del proceso con Id 1008.

.EXAMPLE
    Get-ProcessMolules 
    
    Muestra los módulos principales de todos los procesos en memoria.

.EXAMPLE
    Get-ProcessMolules -AllModules
    
    Muestra todos los módulos de todos los procesos en memoria.


#>

function Get-ProcessMolules
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (

        # Permite filtrar los módulos por Id de proceso.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [int]$Id,

        # Permite filtrar los módulos por nombre de proceso.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$ProcessName,

        # Muestra todos los módulos, tanto principales como secundarios. 
        # Si no se especifica sólo se muestran los módulos principales.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [switch]$AllModules

        
    )

    # Obtenemos los procesos 
    $procesos = ps | where {$_.Id -match $id -and $_.Name -match $ProcessName}
    
    
    # La siguiente variable presenta una estructura de datos para guardar
    # los módulos usados por los procesos en memoria. Incluye tanto 
    # el módulo principal como el resto de módulos.
    # Es un array en el que cada entrada se compone de los campos:
    #   Id del proceso 
    #   Nombre del proceso
    #   Si es modulo principal o no
    #   Ruta completa del módulo
    #   La firma resumen hash de SHA256

    $ModulosProcesos = @()
	
    # Por cada proceso recuperado obtenemos su módulo principal 
    # y lo almacenamos en el array $ModulosProcesos
    foreach ($proceso in $Procesos )
    {
        # Extraemos el módulo principal
        $obj = New-Object PSObject 
        $obj | Add-Member Id $proceso.id
        $obj | Add-Member Name $proceso.name
        # El siguiente campo nos permite diferenciar los módulos 
        # principales de los que no lo son.
        $obj | Add-Member MainModule $true
        # Comprobamos que existe módulo principal
        # en caso contrario no calculamos el hash, para evitar error.
        if ($proceso.MainModule.FileName -eq $null)
        {
            $obj | Add-Member SHA256 $null
        }
        else
        {
            $obj | Add-Member SHA256 (Get-FileHash -Algorithm SHA256 -Path $proceso.MainModule.FileName).Hash
        }
        $obj | Add-Member ModuleName $proceso.MainModule.FileName
        # Añadimos la entrada al array $ModulosProcesos.
        $ModulosProcesos = $ModulosProcesos + $obj
        
        # Recuperamos los módulos no principales, sólo en el caso
        # de que se proporcione el parámetro "-AllModules".
        if ($AllModules) 
        {
            $modulos = $proceso.Modules
            # Para cada módulo no principal recuperado
            # creamos una entrada.
            foreach ($modulo in $modulos)
            {
                $obj = New-Object PSObject 
                $obj | Add-Member Id $proceso.id
                $obj | Add-Member Name $proceso.name
                # El siguiente campo nos permite diferenciar los módulos 
                # principales de los que no lo son.
                $obj | Add-Member MainModule $false
                # Comprobamos que existe módulo en caso contrario
                # no calculamos el hash, para evitar error.
                if ($modulo.FileName -eq $null)
                {
                    $obj | Add-Member SHA256 $null
                }
                else
                {
                    $obj | Add-Member SHA256 (Get-FileHash -Algorithm SHA256 -Path $modulo.FileName).Hash
                }
                $obj | Add-Member ModuleName $modulo.FileName

                # Insertamos cada uno de los módulos no 
                # principalesen el array $ModulosProcesos
                $ModulosProcesos = $ModulosProcesos + $obj
            }
        }
    }
    # Devolvemos el array con los módulos recuperados.
    $ModulosProcesos 
}







<#
.Synopsis
   Obtiene la lista de las rutas de ficheros ejecutables cargados en el arranque.
.DESCRIPTION
   Obtiene la lista de las rutas de ficheros ejecutables cargados en el arranque.
   Y calcula el hash SHA256 de dicha ruta.

.EXAMPLE
    Get-StartupCommand
    
   Obtiene la lista de las rutas de ficheros ejecutables cargados en el arranque.
   Y calcula el hash SHA256 de dicha ruta.

.EXAMPLE
    Get-StartupCommand hot
    
   Obtiene la lista de las rutas de ficheros ejecutables cargados en el arranque,
   cuyo nombre contiene la cadena "hot"
   Y calcula el hash SHA256 de dicha ruta.

#>

function Get-StartupCommand
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (

        # Permite filtrar por nombre, los ficheros ejecutables cargados en el arranque.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Name
        
    )

    # Obtenemos los ficheros  ejecutables que se inician en el arranque.

    $comandos = gwmi Win32_StartupCommand | where-object {$_.Name -match $Name } 

    # La siguiente variable presenta una estructura de datos para guardar
    # la ruta de los ficheros ejecutables cargados en el arranque.
    # Es un array en el que cada entrada se compone de los campos:
    #   Nombre asignado al fichero ejecutable 
    #   Ruta completa del fichero ejecutable 
    #   La firma resumen del fichero ejecutables hash de SHA256

    $ListaComandos = @()
    # Por cada entrada en el arranque
    # obtenemos los diferentes ficheros
    foreach ($comando in $comandos){
        $rutas = $comando.Command
        $rutas = $rutas.split('"')
        $rutas = $rutas  | Where-Object { ($_ -match "\\" ) }| ForEach-Object { $_.Substring(0, $_.lastIndexOf(".") + 4) }
        # Por cada ruta detectada creamos una entrada en $ListaComandos
        ForEach ($ruta in $rutas){
            # Por cada comando sustituimos la variable de entorno de ms-dos 
            # por la de Power-Shell.
            $ruta= $ruta.Replace("%ProgramFiles%",$env:ProgramFiles)
            
            # Creamos una entrada por cada ruta detectada.
            $obj = New-Object PSObject 
            $obj | Add-Member Name $comando.Name
            $obj | Add-Member SHA256 (Get-FileHash -Algorithm SHA256 -Path $ruta).Hash
            $obj | Add-Member Path $ruta
            $ListaComandos = $ListaComandos +$obj
        }
    }
    # Devolvemos la lista de rutas encontradas.
    $ListaComandos 
}










<#
.Synopsis
   Obtiene la lista de las rutas de ficheros usados por los servicios.
.DESCRIPTION
   Obtiene la lista de las rutas de ficheros usados por los servicios.
   Y calcula el hash SHA256 de dicha ruta.
   Se pueden aplicar filtros por el nombre de servicio.
.EXAMPLE
    Get-ServicePatch 
    
   Obtiene la lista de las rutas de ficheros usados por todos los servicios.

.EXAMPLE
    Get-ServicePatch -name adobe
        
   Obtiene la lista de las rutas de ficheros usados por todos 
   los servicios cuyo nombre contiene "adobe"


.EXAMPLE
   (Get-ServicePatch) | select @{Name="Existe"; Expression = {test-path $_.path}}, * | ft -AutoSize


   Obtiene la lista de las rutas de ficheros usados por todos 
   los servicios y comprueba si la ruta existe.
#>

function Get-ServicePatch
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (

        # Permite filtrar los servicios por el nombre.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Name
        
    )

    # Obtenemos los servicios


    $servicios = gwmi Win32_Service |where-object {$_.name -match $Name } 
    $pathposibles = @()
    ForEach ($servicio in $servicios)
    { 
        $rutas = $servicio.pathname
        $rutas = $rutas.split('"')
        $rutas = $rutas  | Where-Object { ($_ -match "\\" ) }| ForEach-Object { $_.Substring(0, $_.lastIndexOf(".") + 4) }
        ForEach ($ruta in $rutas){
            $obj = New-Object PSObject 
            $obj | Add-Member Name $servicio.name
            $obj | Add-Member SHA256 (Get-FileHash -Algorithm SHA256 -Path $ruta).Hash
            $obj | Add-Member PAth $ruta
            $pathposibles = $pathposibles + $obj
        }

    }
    # Devolvemos el array con los elementos correspondietes registros.
    $pathposibles 

}





