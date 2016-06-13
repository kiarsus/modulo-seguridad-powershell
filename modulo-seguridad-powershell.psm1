
# El presente módulo de Powershel intenta solvertar la falta de 
# herramientas para el profesional de seguridad TIC a la hora de 
# trabajar con los sistemas opererativos Windows, para análisis 
# forense, monitorización de eventos y contención de determinados 
# ataques.
#
#
# El presente módulo lo dividimos en varios apartados atendiendo a 
# los recursos usados para la recogida de evidencias, monitorización 
# de eventos y la contención de determinados ataques:
# 
#    * Memoria (procesos y servcios)
#    * Almacenamiento en disco
#    * Registro de Windows
#    * Red
# 
# Ahora se encuentran todos en el mismo módulo pero se preveé su 
# separación en diferentes módulos













#  Módulo de red
# Este apartado comprende los recuros para trabajar con la red entre
# los que se incluye:
#
#   *  Listar tabla arp del equipo local.
#   *  Listar el fabricante de una .
#   *  Listar tabla arp del equipo local.
#   *  Listar tabla arp del equipo local.
#   *  Listar tabla arp del equipo local.
#   
#-----------------------------------------------------------





function Get-ArpTable{

<#     
.SYNOPSIS     
    Devuelve la tabla arp de la máquina actual.   
     $
.DESCRIPTION   
    Devuelve la tabla arp de la máquina actual, con el siguiente tipo de datos:   

   TypeName: Selected.System.String

Name        MemberType   Definition                         
----        ----------   ----------                         
Equals      Method       bool Equals(System.Object obj)     
GetHashCode Method       int GetHashCode()                  
GetType     Method       type GetType()                     
ToString    Method       string ToString()                  
IP          NoteProperty System.String IP=    
MAC         NoteProperty System.String MAC=




                  
.NOTES     
    Nombre:  Get-ArpTable   
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-ArpTable 
    Devuelve la tabla arp de la máquina actual.



#>    


[cmdletbinding(
    ConfirmImpact= 'low'
)]  


   $TablaArp =arp -a | where { $_ -match "[a-f0-9][a-f0-9]-" } | ForEach-Object {$_.trim()} | ForEach-Object {$_.substring(0,$_.LastIndexOf(" "))} |ForEach-Object {$_.trim()} | ForEach-Object{$_.Replace( $_.Substring($_.IndexOf(" ") , $_.LastIndexOf(" ") - $_.IndexOf(" ") +1)  ," ")} | select @{Name="IP";Expression={$_.substring(0,$_.IndexOf(" ")) }},@{Name="MAC";Expression={$_.Substring($_.IndexOf(" ")+1, $_.Length - $_.IndexOf(" ")-1)}} -Unique

    # Eliminamos los elementos usados como broadcast
    $TablaArp = $TablaArp | where mac -ne "ff-ff-ff-ff-ff-ff"
    $TablaArp
}





function  MITM
{

<#     
.SYNOPSIS     
    Esta función permite detectar un ataque man in the middle.
    PAra lo cual compara el contenido actual de la tabla ARP y
    otra tabla pasada como parámetro.
    
    Devuelve el par IP-MAC de la máquina que está realizando el ataque.   
     
.DESCRIPTION   
    El parámetro de entrada tiene el formato que sigue, devuelto por
    la función Get-ArpTable:   

   TypeName: Selected.System.String

Name        MemberType   Definition                         
----        ----------   ----------                         
Equals      Method       bool Equals(System.Object obj)     
GetHashCode Method       int GetHashCode()                  
GetType     Method       type GetType()                     
ToString    Method       string ToString()                  
IP          NoteProperty System.String IP="dirección IP"     
MAC         NoteProperty System.String MAC="dirección MAC"


    La salida tiene el formato que sigue:   

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
    Nombre:  Man-In-The-Middle   
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Man-in-the-middle $TablaArp
    En el caso de encontrar un ataque la función
    devuelve el par IP-MAC desde dónde se está realizando.



             
#>    


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



    # como valor de referencia usamos la tabla arp pasada como parámetro $ArpTable 
    # Extraemos el contenido de la tabla arp actual por medio del sigiente comando
    #$TablaArpNow = Get-ArpTable
    
    # elemento de prueba de la función main...
    
    #$TablaArpNow[0].MAC='58-23-8c-54-91-b3'
    #$TablaArpNow[0].IP='10.54.34.217'
    



    #Unimos el contenido de las dos tablas arp
    #$TablaFin = $TablaArpNow + $ArpTable 
    #$ListaMAC = $TablaArpNow | select mac -Unique 


    
    #Si el número de pares IP-MAC es diferente del número de MAC diferentes existen dos equipos con la misma mac, 
    #if ($ListaMAC.count -eq $TablaArpNow.Count)
    #{Write-Host "Existe un ataque man in the middle"
    #$ListaMAC
    #}
    #$false



    #$ArpTable    = Get-ArpTable
    $ArpTableNow = Get-ArpTable
    
    # elemento de prueba de la función main...
     

   $ArpTableNow[1].MAC=$ArpTableNow[0].MAC
   $ArpTableNow[2].MAC=$ArpTableNow[3].MAC
    
    #$ArpTable 

   #  $ArpTableNow


    #Unimos el contenido de las dos tablas arp y recuperamos los pares IP,mac únicos
    $TablaFin = $ArpTableNow  + $ArpTable | select IP,MAC -Unique 
    
    # seleccionamos las MAC que tengan más de una IP
    $TablaGroup = $TablaFin | Group-Object mac | select @{name="MAC"; Expression={$_.name}},@{name="cuantos"; Expression={$_.count}}  | where {$_.cuantos -gt 1}
    # $TablaGroup
    [int]$numataques=$TablaGroup.length
    $iniciado = $false
    #Recorremos las diferentes agrupaccones de mac

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





function Get-MITMRuleFirewall
{
<#     
.SYNOPSIS     
    Esta función muestra las regla en el 
    cortafuegos creada por la función 
    New-MITMRuleFirewall. 
     
.DESCRIPTION   
    No tiene parémetros de entrada
 

.NOTES     
    Nombre: Get-MITMRuleFirewall 
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-MITMRuleFirewall
    Muestra las reglas en el Firewall
    pertenecientes al grupo "MITM"



#>    


[cmdletbinding(
    ConfirmImpact= 'low'
)]  

        
    $Existe= Get-NetFirewallRule  | Where-Object {$_.DisplayGroup -eq "MITM"}
    
    $Existe
}




function Exists-MITMRule
{
<#     
.SYNOPSIS     
    Esta función comprueba si existe una regla en el 
    cortafuegos creada por la función 
    New-MITMRuleFirewall. 
     
.DESCRIPTION   
    El parámetro de entrada es el nombre de la regla
    con el formato "MITM-In-" + DirecciónIP
 

.NOTES     
    Nombre: Exist-MITMRule 
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Exist-MITMRule "MITM-In-192.168.53.2"
    Si encuentra la regla devuelve "True", en caso 
    contrario devuelve "False"


             
#>    


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






function New-MITMRuleFirewall
{

<#     
.SYNOPSIS     
    Esta función crea una regla en el cortafuegos para 
    bloquear una IP, tanto en el flujo de entrada como
    en el flujo de salida. 
    Si ya está bloqueada no hace nada.
    
    El nombre de la reglas creadas es la concatenación de 
    "MITM-In" + "IP A BLOQUEAR"   para flujo de entrada
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
    Si no está bloqeada, crea las reglas en el 
    cortafuegos:
    "MITM-In-192.168.53.2"
    "MITM-Out-192.168.53.2"


#>    


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

    
    if (-not (Exists-MITMRule $RuleNameIn)){
        $Papelera=New-NetFirewallRule -DisplayName $RuleNameIn  -Action Block -Direction Inbound  -Enabled True -InterfaceType Any -Profile Any -RemoteAddress $IpAddress -Group "MITM"
        $Papelera=New-NetFirewallRule -DisplayName $RuleNameOut -Action Block -Direction Outbound -Enabled True -InterfaceType Any -Profile Any -RemoteAddress $IpAddress -Group "MITM"
    }
}








function Remove-MITMRuleFirewall
{

<#     
.SYNOPSIS     
    Esta función elimina una regla en el cortafuegos que 
    boquea una IP, tanto en el flujo de entrada como
    en el flujo de salida. 
    Si no existe no hace nada.
    
    El nombre de la reglas eliminadas es la concatenación de 
    "MITM-In" + "IP A BLOQUEAR"   para flujo de entrada
    "MITM-Out" + "IP A BLOQUEAR"   para flujo de salida
     
     También permite eliminar todas las reglas existentes
     si el parámetro $All lo igualamos a True

.DESCRIPTION   
    Los parámetro de entrada son:
    
    System.Net.IPAddress.
    y
    System.Boolean

.PARAMETER IpAddress

    Es una Dirección IP cuyo tipo es [System.Net.IpAddress]

.PARAMETER $All 
    Es un Boleano que cuando se iguala a True se eliminan 
    todas las reglas del Grupo MITM

.NOTES     
    Nombre:  DesBloquear-MITM
    Necesita el módulo NetSecurity para su funcionamiento
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Remove-MITMRuleFirewall [IPAddress]"192.168.53.2"
    Si existe elimina las reglas del cortafuegos
    "MITM-In-192.168.53.2"
    "MITM-Out-192.168.53.2"

.EXAMPLE    
    Remove-MITMRuleFirewall -All $True
    Elimina todas las reglas del grupo MITM
 



#>    


[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
        #    Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.Net.IPAddress]$IpAddress,
        [Parameter(  
        #    Mandatory = $True,  
            Position = 1,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.Boolean]$RemoveAll
      ) 

    
    if ($RemoveAll -eq $false){

        # creamos el nombre de las reglas
        $RuleNameIn= "MITM-In-"  + $IpAddress.ToString()
        $RuleNameOut="MITM-Out-" + $IpAddress.ToString()

    
        if (Exists-MITMRule $RuleNameIn){
            $Papelera=Remove-NetFirewallRule -DisplayName $RuleNameIn
            $Papelera=Remove-NetFirewallRule -DisplayName $RuleNameOut
        }
    } else{
        Get-MITMRuleFirewall | Remove-NetFirewallRule
    }

}





function Get-ListNetworkProviders{

<#     
.SYNOPSIS     
    Devuelve una tabla con los nombre de los Fabricantes de adaptadores de red 
    y los primeros seis caracteres de la mac. 
    Se necesita acceso a Internet para poder recuperar la lista actualizada.  
     
.DESCRIPTION   
    Devuelve una tabla con los nombre de los Fabricantes de red y sus primeros
    seis caracteres de la mac, con el siguiente tipo de datos:   

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
    Devuelve la tabla de fabricantes de adaptadores de red y 
    los seis primeros caracteres de la mac.



#>    


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




function Get-NetworkProviderMAC{

<#     
.SYNOPSIS     
    Devuelve los seis caracteres de la mac de un nombre de Fabricantes de 
    adaptadores de red pasado como parametro.  
     
.DESCRIPTION   
    Devuelve los seis caracteres de la mac de un nombre de Fabricantes de 
    adaptadores de red pasado como parametro.  
    Como parámetro recibe el nombre del fabricante, cadena de texto
    y la tabla de fabricantes del siguiente tipo.

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
    Nombre:  Get-NetworkProviderMAC  
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-NetworkProviderMAC $TablaProveedores""
    Devuelve la tabla de fabricantes de adaptadores de red y 
    los seis primeros caracteres de la mac.



#>    


[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.object]$TableProvider,
        [Parameter(  
            Mandatory = $True,  
            Position = 1,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.String]$NameProvider
        ) 

    
    ($TableProvider | where provider -Match $NameProvider).mac
}





function Get-NetworkProviderName{

<#     
.SYNOPSIS     
    Devuelve el nombre del Fabricante de adaptador de red. PAra lo que se 
    pasa como parametro una cadena de carateres de los primeros seis 
    caracteres de la mac.
     
.DESCRIPTION   
    Devuelve el nombre del Fabricante de adaptador de red. PAra lo que se 
    pasa como parametro una cadena de carateres de los primeros seis 
    caracteres de la mac.
    Como parámetro recibe los seis primeros caracteres de la mac, 
    cadena de texto y la tabla de fabricantes del siguiente tipo.

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
    Nombre:  Get-NetworkProviderMAC  
    Author: Enrique Parras Garrido  
    DateCreated: 12 de mayo 2015    
        

.EXAMPLE    
    Get-NetworkProviderName 
    Devuelve la tabla de fabricantes de adaptadores de red y 
    los seis primeros caracteres de la mac.



#>    


[cmdletbinding(
    ConfirmImpact= 'low'
)]  

 Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.object]$TableProvider,
        [Parameter(  
            Mandatory = $True,  
            Position = 1,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [System.String]$MacProvider
        ) 

    
    ($TableProvider | where mac -Match $MacProvider).provider
}









#  módulo  de ficheros o sistema de archivo





# Este apartado implementa las funciones que permiten
# trabajar con ficheros .PST usados 
#
#
# trabajar con ficheros PST 
#--------------------------------------------------------------


<#
.Synopsis
   Abre un fichero PST para poder trabajar con él.
.DESCRIPTION
   Abre un fichero PST para poder trabajar con él.
   En el caso de que ya esté abierto, no hace nada.
.OUTPUTS
   Devuelve la ruta del fichero PST que se acaba de abrir
   Es una cadena de texto

.EXAMPLE
   El siguiente ejemplo abre el fichero "myfilepst.pst" para trabajar con él.

   $a = Open-PSTFile myfilepst.pst

EXAMPLE
   El siguiente ejemplo abre todos los ficheros PST contenidos en el directorio
   por defecto donde se almacenan los ficheos PST del usuario actual.
   En la variable $a sólo se almacenará una estructura PST, correspondiente
   con la del último PST abierto
   $a =  (ls $env:LOCALAPPDATA\Microsoft\Outlook\*.pst).FullName  | Where-Object{open-PSTFile $_ } 
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

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
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
.OUTPUTS
   Devuelve <boolean> 
   True  - si se encuentra abierto
   False - si no se encuentra abiert
.EXAMPLE
   El siguiente ejemplo comprueba si el fichero "myfilepst.pst" 
   se encuentra abierto.
   Y en $a almacena la estructura para trabajar con él.
    
    IsOpen-PSTFile myfilepst.pst
.EXAMPLE
   El siguiente ejemplo comprueba cuales de los ficheros 
   .PST del directorio "c:\midirectorio", se encientran abiertos.
    
    IsOpen-PSTFile myfilepst.pst

    ls  'c:\midirectorio\*.pst'  | select  @{Name="Abierto"; Expression = {IsOpen-PSTFile $_.FullName}},@{Name="Fichero .PST"; Expression = {$_.FullName}} | ft -AutoSize
#>

function IsOpen-PSTFile
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
   Devuelve la ruta del fichero .PST, que es el almacén por defecto.
.DESCRIPTION
   Devuelve la ruta del fichero .PST, que es el almacén por defecto.
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
   El siguiente ejemplo devuelve la ruta del fichero .PST, 
   que es el almacén por defecto.
    
   Get-PSTFileDefault
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
   Devuelve la ruta de los fichero .PST, que se encuentran abiertos.
.DESCRIPTION
   Devuelve la ruta de los fichero .PST, que se encuentran abiertos.
.OUTPUTS
   Devuelve <String> 
.EXAMPLE
   El siguiente ejemplo devuelve la ruta de los ficheros .PST, que se
   encuentran abiertos
    
   Get-PSTOpenFiles
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
   Cierra un fichero PST para que nos sea accesible desde el entorno de Microsoft Outlook.
   No se podrá cerrar el PST asignado al perfil por defecto.
.DESCRIPTION
   Cierra un fichero PST para que nos sea accesible desde el entorno de Microsoft Outlook.
   No se podrá cerrar el PST asignado al perfil por defecto.
.EXAMPLE
   El siguiente ejemplo cierra el fichero "myfilepst.pst"
   
   Close_PSTFile myfilepst.pst

EXAMPLE
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   por defecto donde se almacenan los ficheos PST del usuario actual.

   ls $env:LOCALAPPDATA\Microsoft\Outlook\*.pst | Close-PSTFile

EXAMPLE
   El siguiente ejemplo cierra todos los ficheros PST abiertos.

   Get-PSTOpenFiles | ForEach-Object { Close-PSTFile $_.FilePath}
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
   Lista los directorios contenidos en un ficheros .PST.
.DESCRIPTION
   Lista los directorios contenidos en un ficheros .PST.
   En esta lista se incluyen recuros como los contactos, 
   el calendario, Fuentes RSS entre otras. 
.EXAMPLE
   El siguiente ejemplo lista los directorios del .PST myfilepst.pst

   Get-PSTListDirectory myfilepst.pst

#>

function Get-PSTListDirectory
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST que queremos listar directorios.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST
    )

        <#
        .Synopsis
           Lista los directorios contenidos en un ficheros .PST.
        .DESCRIPTION
           Lista los directorios contenidos en un ficheros .PST.
           En esta lista se incluyen recuros como los contactos, 
           el calendario, Fuentes RSS entre otras. 
        .EXAMPLE
           El siguiente ejemplo lista los directorios del un fichero .PST
           Para ello debnemos pasar como parámetro al objeto raiz del fichero
           .PST
           
           Get-PSTListDirectory $ObjRaizPST

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
    
            # Iniciamos con la lista vacía para poder hacer la
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
                #lista recursiva de la carpeta i
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
        # cerramos el .PST siempre que sea diferente del almacen por defecto
        if ( ($namespace.Folders.Item($i).Store.FilePath -eq $pathfilePST))
        {
           $RootFolder = ($namespace.Folders.Item($i).Store).GetRootFolder()
           break
        }
    }    

    
    # Llamamos a la función auxiliar con el objeto
    # que representa la raíz del fichero .PST paso 
    # como parámetro.
    Get-PSTListDirectoryAux $RootFolder

    $RootFolder
}














# Este apartado implementa las funciones que permiten
# la eliminación de ficheros temporales tanto propios
# del usuario como del sistema.
#
#


#-------------------------------------------------------
















<#
.Synopsis
   Obtiene una lista de los usuarios existentes en pc.
   Puede que esos usuarios no hayan iniciado sesión y
   que su directorio personal no exista.
   
.DESCRIPTION
   Obtiene una lista de los usuarios existentes
.EXAMPLE
   El siguiente ejemplo otiene una lista de los usuarios existentes 
   Get-UserList
.EXAMPLE
   El siguiente ejemplo calcula el directorio personal de los usuarios del pc.

   Get-UserList | select  @{Name="Path"; Expression = {(($env:USERPROFILE.Substring(0,$env:USERPROFILE.LastIndexOf("\") +1)) + $_.user)}} | ft -AutoSize

.EXAMPLE
   El siguiente ejemplo calcula el directorio personal de los usuarios del pc. Y dice cuales existen
   
   Get-UserList | select  @{Name="Existe"; Expression = {(Test-Path (($env:USERPROFILE.Substring(0,$env:USERPROFILE.LastIndexOf("\") +1)) + $_.user))}}, @{Name="Path"; Expression = {(($env:USERPROFILE.Substring(0,$env:USERPROFILE.LastIndexOf("\") +1)) + $_.user)}} | ft -AutoSize
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
   Elimina contenido de un directorio
.DESCRIPTION
   Elimina contenido de un directorio
.EXAMPLE
   El siguiente ejemplo elimina el contenido del directorio "c:\tmp\poupelle" 
   Remove-DirectoryContent -pathfileordirectory "c:\tmp\poupelle" 
.EXAMPLE
   El siguiente ejemplo elimina el contenido del directorio "c:\tmp\poupelle" 
   Con las credenciales almacenadas en la variable $cred
   Remove-DirectoryContent -pathfileordirectory "c:\tmp\poupelle" -Credential $cred
.EXAMPLE
   El siguiente ejemplo elimina el contenido del directorio "c:\tmp\poupelle" 
   Para ello pide las credenciales 
   Remove-DirectoryContent -pathfileordirectory "c:\tmp\poupelle" -Credential (Get-Credential)

#>

function Remove-DirectoryContent
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
        # Directorio del que queremos eliminar el contenido
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el directorio: $_"}})]        
        [string]$pathfileordirectory,

        # Credenciales/permisos con los que vamos a eliminar el contenido del directorio 
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
   Elimina ficheros temporales de la máquina

.DESCRIPTION
   Elimina los ficheros temporales de un ordenador. Permite
   parámetros para seleccionar que ficheros eliminar
   y con qué credenciales.

.EXAMPLE    
    Remove-FileTemp -CurrentUser -Prefetch -WindowsTemp -InternetCache -Credential Get-Credential
    Elimina la siguiente lista de temporales con las credenciales que pide al usuario.
        - temporales del usuario actual 
        - los ficheros PRefetch 
        - temporales de windows
        - temorales de internet explorer
        
.EXAMPLE
     
     Remove-FileTemp -Cookies -History -Recent

     Con este ejemplo se eliminan:
        - las cookies
        - el historial de navegación de Explorer e Internet Explorer
        - los ficheros recientes
.EXAMPLE

   El siguiente ejemplo elimina los ficheros temporales del usuario
   
   Remove-FileTemp -currentuser 

#>
function Remove-FileTemp

{
    [CmdletBinding(ConfirmImpact='Medium')]
    
    Param
    (

        # Indica si el borrado se hará de los temporales del usuario actual
        # no es compatible con el parámentro $user, ni $alluser.
        # Solo puede usarse uno de los parámetros.
        [Parameter()]
        #[ValidateScript({if((-not $User) -and (-not $AllUser)) {$true} else{Throw "Sólo puede especificarse un parámetro: -AllUser -CurrentUser o -User."}})]
        [switch]$CurrentUser,

        # Posibles mejoras para incluir todos los usuarios o un usuario concreto
        # Indica que el borrado se hará de los temporales de todos los usuarios del pc 
        # no es compatible con el parámentro $CurrentUser, ni $alluser.
        # Solo puede usarse uno de los parámetros.
        #[Parameter()]
        #[ValidateScript({if((-not $CurrentUser) -and (-not $User)) {$true} else{Throw "Sólo puede especificarse un parámetro: AllUser CurrentUser o User."}})]
        #[switch]$AllUser,

        # Indica si el borrado se hará sobre el usuario especificado.
        # no es compatible con el parámentro $CurrentUser, ni $alluser.
        # Solo puede usarse uno de los parámetros.
        #[Parameter(ValueFromPipeline=$true,
        #           ValueFromPipelineByPropertyName=$true)]
        #[ValidateScript({if((-not $CurrentUser) -and (-not $AllUser)) {$true} else{Throw "Sólo puede especificarse un parámetro: AllUser CurrentUser o User."}})]
        #[string]$User,

        # Indica si el borrado se hará además del directorio prefech
        [Parameter()]
        [switch]$Prefetch,

        # Indica si el borrado se hará del directorio temp de windows
        [Parameter()]
        [switch]$WindowsTemp,

        # Indica si el borrado se hará sobre los temporales del
        # Internet Explorer
        [Parameter()]
        [switch]$Cookies,

        # Indica si el borrado se hará sobre los temporales del
        # Internet Explorer
        [Parameter()]
        [switch]$History,

        # Indica si el borrado se hará sobre los temporales del
        # Internet Explorer
        [Parameter()]
        [switch]$Recent,


        # Indica si el borrado se hará sobre los temporales del
        # Internet Explorer
        [Parameter()]
        [switch]$InternetCache,

        # Credenciales/permisos con los que vamos a eliminar
        [Parameter()]
        [PSCredential]$Credential
    )

    # directorio prefetch de windows
    # probado para windows 8 , 8.1
    if ($Prefetch){
        if ($Credential){
            Remove-DirectoryContent ($env:windir + "\Prefetch") -Credential $Credential 
        } else{
            Remove-DirectoryContent ($env:windir + "\Prefetch") 
        }
    }

    # directorio temp de windows
    # probado para windows 8 , 8.1
    if ($WindowsTemp){
       # $dirpref=$env:windir + "\Temp"
        if ($Credential){
            Remove-DirectoryContent ($env:windir + "\Temp") -Credential $Credential 
        } else{
            Remove-DirectoryContent ($env:windir + "\Temp") 
        }
    }

    # directorio temp del usuario actual
    # probado para windows 8 , 8.1
    if ($CurrentUser){
       # $dirpref=$env:windir + "\Temp"
        if ($Credential){
            Remove-DirectoryContent $env:tmp  -Credential $Credential 
        } else{
            Remove-DirectoryContent $env:tmp  
        }
    }

# Para acceso a las Environment.SpecialFolder se hace uso de las especificaciones
# que aparecen en el sigueinte enlace 
# https://msdn.microsoft.com/es-es/library/system.environment.specialfolder(v=vs.110).aspx    
#
    # directorio Cookies del usuario actual
    # probado para windows 8 , 8.1
    if ($Cookies){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("Cookies"))  -Credential $Credential 
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("Cookies"))
        }
    }
    
    # directorio Cookies del usuario actual
    # probado para windows 8 , 8.1
    if ($History){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("History"))  -Credential $Credential 
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("History"))
        }
    }

    # directorio temporal de IE del usuario actual
    # probado para windows 8 , 8.1
    if ($InternetCache){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache"))  -Credential $Credential 
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache") + "\IE")  -Credential $Credential 

        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache"))
            Remove-DirectoryContent ([Environment]::GetFolderPath("InternetCache") + "\IE") 
        }
    }


    
    # directorio de documentos abiertos recientemente
    # probado para windows 8 , 8.1
    if ($Recent){
        if ($Credential){
            Remove-DirectoryContent ([Environment]::GetFolderPath("Recent"))  -Credential $Credential 
        } else{
            Remove-DirectoryContent ([Environment]::GetFolderPath("Recent"))
        }
    }


   
}













# Este apartado implementa las funciones que permiten
# trabajar con ficheros .PST usados 
#
#
# trabajar con ficheros PST 
#--------------------------------------------------------------


<#
.Synopsis
   Abre un fichero PST para poder trabajar con él.
.DESCRIPTION
   Abre un fichero PST para poder trabajar con él.
   En el caso de que ya esté abierto, no hace nada.
.OUTPUTS
   Devuelve la ruta del fichero PST que se acaba de abrir
   Es una cadena de texto

.EXAMPLE
   El siguiente ejemplo abre el fichero "myfilepst.pst" para trabajar con él.

   $a = Open-PSTFile myfilepst.pst

EXAMPLE
   El siguiente ejemplo abre todos los ficheros PST contenidos en el directorio
   por defecto donde se almacenan los ficheos PST del usuario actual.
   En la variable $a sólo se almacenará una estructura PST, correspondiente
   con la del último PST abierto
   $a =  (ls $env:LOCALAPPDATA\Microsoft\Outlook\*.pst).FullName  | Where-Object{open-PSTFile $_ } 
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

    Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null 
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
.OUTPUTS
   Devuelve <boolean> 
   True  - si se encuentra abierto
   False - si no se encuentra abiert
.EXAMPLE
   El siguiente ejemplo comprueba si el fichero "myfilepst.pst" 
   se encuentra abierto.
   Y en $a almacena la estructura para trabajar con él.
    
    IsOpen-PSTFile myfilepst.pst
.EXAMPLE
   El siguiente ejemplo comprueba cuales de los ficheros 
   .PST del directorio "c:\midirectorio", se encientran abiertos.
    
    IsOpen-PSTFile myfilepst.pst

    ls  'c:\midirectorio\*.pst'  | select  @{Name="Abierto"; Expression = {IsOpen-PSTFile $_.FullName}},@{Name="Fichero .PST"; Expression = {$_.FullName}} | ft -AutoSize
#>

function IsOpen-PSTFile
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
   Devuelve la ruta del fichero .PST, que es el almacén por defecto.
.DESCRIPTION
   Devuelve la ruta del fichero .PST, que es el almacén por defecto.
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
   El siguiente ejemplo devuelve la ruta del fichero .PST, 
   que es el almacén por defecto.
    
   Get-PSTFileDefault
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
   Devuelve la ruta de los fichero .PST, que se encuentran abiertos.
.DESCRIPTION
   Devuelve la ruta de los fichero .PST, que se encuentran abiertos.
.OUTPUTS
   Devuelve <String> 
.EXAMPLE
   El siguiente ejemplo devuelve la ruta de los ficheros .PST, que se
   encuentran abiertos
    
   Get-PSTOpenFiles
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
   Cierra un fichero PST para que nos sea accesible desde el entorno de Microsoft Outlook.
   No se podrá cerrar el PST asignado al perfil por defecto.
.DESCRIPTION
   Cierra un fichero PST para que nos sea accesible desde el entorno de Microsoft Outlook.
   No se podrá cerrar el PST asignado al perfil por defecto.
.EXAMPLE
   El siguiente ejemplo cierra el fichero "myfilepst.pst"
   
   Close_PSTFile myfilepst.pst

EXAMPLE
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   por defecto donde se almacenan los ficheos PST del usuario actual.

   ls $env:LOCALAPPDATA\Microsoft\Outlook\*.pst | Close-PSTFile

EXAMPLE
   El siguiente ejemplo cierra todos los ficheros PST abiertos.

   Get-PSTOpenFiles | ForEach-Object { Close-PSTFile $_.FilePath}
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
   Lista los directorios contenidos en un ficheros .PST.
.DESCRIPTION
   Lista los directorios contenidos en un ficheros .PST.
   En esta lista se incluyen recuros como los contactos, 
   el calendario, Fuentes RSS entre otras. 
.EXAMPLE
   El siguiente ejemplo lista los directorios del .PST myfilepst.pst

   Get-PSTListDirectory myfilepst.pst

EXAMPLE
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
   El siguiente ejemplo cierra todos los ficheros PST contenidos en el directorio
#>

function Get-PSTListDirectory
{
    [CmdletBinding(ConfirmImpact='Medium')]
    Param
    (
            # Ruta del fichero .PST que queremos listar directorios.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({If(Test-Path $_){$true}else{Throw "No se encuentra el fichero .PST: $_"}})]        
        [string]$pathfilePST
    )

        <#
        .Synopsis
           Lista los directorios contenidos en un ficheros .PST.
        .DESCRIPTION
           Lista los directorios contenidos en un ficheros .PST.
           En esta lista se incluyen recuros como los contactos, 
           el calendario, Fuentes RSS entre otras. 
        .EXAMPLE
           El siguiente ejemplo lista los directorios del un fichero .PST
           Para ello debnemos pasar como parámetro al objeto raiz del fichero
           .PST
           
           Get-PSTListDirectory $ObjRaizPST

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
    
            # Iniciamos con la lista vacía para poder hacer la
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
                #lista recursiva de la carpeta i
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
        # cerramos el .PST siempre que sea diferente del almacen por defecto
        if ( ($namespace.Folders.Item($i).Store.FilePath -eq $pathfilePST))
        {
           $RootFolder = ($namespace.Folders.Item($i).Store).GetRootFolder()
           break
        }
    }    

    
    # Llamamos a la función auxiliar con el objeto
    # que representa la raíz del fichero .PST paso 
    # como parámetro.
    Get-PSTListDirectoryAux $RootFolder

    $RootFolder
}










