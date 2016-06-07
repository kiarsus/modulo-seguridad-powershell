
# El presenete módulo de Powershel intenta solvertar la falta de 
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














# Este apartado comprende los recuros para trabajar con la red entre
# los que se incluye:
#
#   *  Listar tabla arp del equipo local.
#   *  Listar el fabricante de una .
#   *  Listar tabla arp del equipo local.
#   *  Listar tabla arp del equipo local.
#   *  Listar tabla arp del equipo local.
#   
#



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




