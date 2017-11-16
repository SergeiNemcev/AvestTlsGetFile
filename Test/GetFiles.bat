@echo off
set dd=%DATE:~0,2%
set mm=%DATE:~3,2%
set yyyy=%DATE:~6,4%
set dat_bgn=%yyyy%-%mm%-01
set dat_end=%yyyy%-%mm%-%dd%


echo Данные по заявкам месплана (ГУ-12) за текущий месяц в формате XML:
rem запуск команд в отдельном процессе с ожиданием завершения
@echo on
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/export?dat_bgn=%dat_bgn%^&dat_end=%dat_end% file:"\Download\Mesplan.xml"

@echo НСИ, используемые в АС в формате XML:

start /wait AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=ACCOMP_FORMS file:"\Download\ACCOMP_FORMS.xml" 
start /wait AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=CARGO file:"\Download\CARGO.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=CARGO_ETSNG_GNG file:"\Download\CARGO_ETSNG_GNG.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=CARGO_GNG file:"\Download\CARGO_GNG.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=FORWARD_BCH file:"\Download\FORWARD_BCH.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=FORWARDER file:"\Download\FORWARDER.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=LOCKING_ARM file:"\Download\LOCKING_ARM.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=MANAGEMENT file:"\Download\MANAGEMENT.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=MASS file:"\Download\MASS.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=ROAD file:"\Download\ROAD.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=STA file:"\Download\STA.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=TARE_SMGS file:"\Download\TARE_SMGS.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=VAGON_KIND file:"\Download\VAGON_KIND.xml" 
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/downloadNSI?type=XML^&table=VAGON_TYPE file:"\Download\VAGON_TYPE.xml" 


@echo Жд накладные - в формате ZIP, который содержит перечень подписанных накладных в формате P7B (обвертка для XML):
start /wait  AvestTLS_GetFile.exe conf:"\MyConfig\Config.ini" log:"\Log\Test.log" from:/ep/exportDocs?doc_type=nakl^&eids=3942697,3942612,3942588 file:"\Download\Nakl.zip" 


@echo off
TIMEOUT /T 30 