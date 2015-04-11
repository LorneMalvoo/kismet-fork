#Kismet-fork
Fork de kismet pour le PJI elasticsearch et audit wifi
Par Mahieddine Yaker
(mahieddine DOT yaker (AT) gmail DOT com)

####Requis :

   - Elasticsearch installé
   - Kismet installé depuis le git (suivre le Readme présent dans le dossier Kismet)

Modifiez le fichier /usr/local/etc/kismet.conf pour specifier ces Informations :

   - Serveur gpsd avec la variable gpshost
   - Path pour les logs de Kismet (de préférence /var/log/kismet) à specifier avec la variable logprefix

####UTILISATION

Lancez un scan avec Kismet installé sur votre machine (/usr/local/kismet -c INTERFACE).
Une fois cela effectué, executez le serveur elasticsearch.
Lancez le script script.py avec python3, si necessaire, modifiez le nom du répertoire des logs kismet dans le script (variablle PATH_LOG).
Puis allez dans le dossier de kibana, modifiez si necessaire le fichier config/kibana.yml, et allez sur "MONSERVER:5601" avec un navigateur.
