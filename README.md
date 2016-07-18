# modulo-seguridad-powershell
 
 
   El presente fichero forma parte del módulo de PowerShell, 
 “modulo-seguridad-powershell”, desarrollado para el Trabajo 
 Fin de Grado del “Curso de adaptación al Grado de Ingeniería
 Informática, de la Universidad Internacional de la Rioja.

   Dicho trabajo se encuentra Publicado en el repositorio 
 Git-Hub, bajo la licencia GNU General Public License.
 https://github.com/kiarsus/modulo-seguridad-powershell
 
   Trabajo realizado única y exclusivamente por el Alumno: 
 Enrique Parras Garrido.






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
continuación ejecute los siguientes comandos. El primero es para 
dar permisos de ejecución al usuario actual y el segundo instala 
el módulo: 


Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted 

Invoke-Expression (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/kiarsus/modulo-seguridad-powershell/master/install.ps1")

 
