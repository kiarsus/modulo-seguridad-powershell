# modulo-seguridad-powershell
 
 

 El presenete módulo de Powershel intenta solvertar la falta de 
 herramientas para el profesional de seguridad TIC a la hora de 
 trabajar con los sistemas opererativos Windows, para análisis 
 forense, monitorización de eventos y contención de determinados 
 ataques.


 El presente módulo lo dividimos en varios apartados atendiendo a 
 los recursos usados para la recogida de evidencias, monitorización 
 de eventos y la contención de determinados ataques:
 
    * Memoria (procesos y servcios)
    * Almacenamiento en disco
    * Registro de Windows
    * Red

Para instalar el presente módulo abra el entorno powershell y a 
continuación ejecute el siguiente comando: 


Invoke-Expression (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/kiarsus/modulo-seguridad-powershell/master/install.ps1")
