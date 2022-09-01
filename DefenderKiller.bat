:Start
@echo off

Rem Enable Delayed Expansion
setlocal EnableDelayedExpansion

color 0f
Title DefenderKiller

rem Переменные
set "sFreeSize="
set "sFreeSizePseudoMb1="
set "Freed="
set "ch=cecho.exe"

rem UAC
reg query "HKU\S-1-5-19\Environment" >nul 2>&1 & cls
if "%Errorlevel%" NEQ "0" (
PowerShell -WindowStyle Hidden -NoProfile "Start-Process '%~dpnx0' -WindowStyle Normal -Verb RunAs" && exit
)

rem Если защитник существует - перед запуском проверяем, чтобы защита в реальном времени была отключена - без этого НЕ скачается FuckDefender
if exist "%SystemDrive%\Program Files\Windows Defender" (
reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" >nul 2>&1 || call :CheckOff
)

rem Check Ethernet, DownLoad Files, Check Update
if not exist %SystemDrive%\DefenderKiller call :DownLoadFile 

rem Запуск .bat от имени TI
if /i not "%USERNAME%"=="SYSTEM" "%SystemDrive%\DefenderKiller\TI.exe" "%~f0" %* & exit

rem Переходим в рабочий каталог
cd /d "%SystemDrive%\DefenderKiller"

ConX.exe show

rem Проверяем обновления
call :CheckUpdate

rem 740
@cmdow @ /SIZ 1000 715

rem Цвет консоли и тд
reg query "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" >nul 2>&1 || call :ModifedCMD

qprocess "Win 10 Tweaker.exe">nul 2>&1 || nircmd.exe win center alltop


cls

%ch% {0f}DefenderKiller Версия: {0b}8.3{#}
if "%Version%" EQU "!latestVersion!" (
%ch% {0a} [Вы используете актуальную версию]{\n #}
) else (
%ch% {0c} [Версия является устаревшей]{\n #}
)
%ch% {0f}Запущено с правами: {0e}%username%{\n #}
echo.
%ch% {03}Состояние защитника Windows:{\n #}
if not exist "%ProgramFiles%\Windows Defender" (
%ch% {02}Удален из Windows{08} [папка Windows Defender удалена]{\n #}
) else (
%ch% {04}Не удален из Windows{\n #}
)

rem Win 8.1
VER | FINDSTR /IL "6.3." > NUL
IF %ERRORLEVEL% EQU 0 (goto Proc)

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" >nul 2>&1
if "%ERRORLEVEL%"=="0" (%ch% {0a}Защитник отключен {08}[ключ реестр DisableAntiSpyware]{\n #})
if "%ERRORLEVEL%"=="1" (%ch% {04}Защитник включен{\n #})

:Proc
echo.

%ch% {03}Состояние процессов защитника:{\n #}

%ch% {0f}MsMpEng      {#}
qprocess "MsMpEng.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (Antimalware Service Executable){\n #}

%ch% {0f}SmartScreen  {#}
qprocess "smartscreen.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (SmartScreen Защитника Windows){\n #}

%ch% {0f}SgrmBroker   {#}
qprocess "SgrmBroker.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (Служба брокера мониторинга среды выполнения System Guard){\n #}

%ch% {0f}Uhssvc Upd.  {#}
qprocess "uhssvc.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (Uhssvc.exe Microsoft Update Health Service){\n #}

%ch% {0f}SecHealthUI  {#}
qprocess "SecHealthUI.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (Безопасность Windows){\n #}

%ch% {0f}NisSrv       {#}
qprocess "NisSrv.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (Network Realtime Inspection){\n #}

%ch% {0f}MpCmdRun     {#}
qprocess "MpCmdRun.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (Microsoft malware protection){\n #}

%ch% {0f}Heal.Systray {#}
qprocess "SecurityHealthSystray.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (SecurityHealthSystray.exe Windows Security notification icon){\n #}

%ch% {0f}Heal.Service {#}
qprocess "SecurityHealthService.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (SecurityHealthService.exe){\n #}

%ch% {0f}SHelath Host {#}
qprocess "SecurityHealthHost.exe">nul 2>&1 && %ch% {04}Процесс запущен{#}|| %ch% {0a}Процесс не запущен{#}
%ch% {08} (SecurityHealthHost.exe){\n #}

echo.
rem Проверка служб и драйверов
%ch% {03}Состояние служб защитника:{\n #}
%ch% {0f}WinDefend {#} 
sc query WinDefend >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}Не существует{\n #}) else (
sc query WinDefend | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключена{\n #}) ELSE (%ch% {04}Запущена{\n #}))

%ch% {0f}WdNisSvc   {#}
sc query WdNisSvc >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}Не существует{\n #}) else (
sc query WdNisSvc | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключена{\n #}) ELSE (%ch% {04}Запущена{\n #}))

%ch% {0f}Sense      {#}
sc query Sense >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}Не существует{\n #}) else (
sc query Sense | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключена{\n #}) ELSE (%ch% {04}Запущена{\n #}))

%ch% {0f}Sec.Health {#}
sc query SecurityHealthService >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}Не существует{\n #}) else (
sc query SecurityHealthService | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключена{\n #}) ELSE (%ch% {04}Запущена{\n #}))

%ch% {0f}wscsvc     {#}
sc query wscsvc >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}Не существует{\n #}) else (
sc query wscsvc | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключена{\n #}) ELSE (%ch% {04}Запущена{\n #}))

%ch% {0f}SgrmBroker {#}
sc query SgrmBroker >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}Не существует{\n #}) else (
sc query SgrmBroker | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключена{\n #}) ELSE (%ch% {04}Запущена{\n #}))

echo.
%ch% {03}Состояние драйверов защитника:{\n #}

%ch% {0f}WdNisDrv:{#} 
sc query WdNisDrv >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}Не существует{#} ) else (
sc query WdNisDrv | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключен{#} ) ELSE (%ch% {04}Запущен{#} ))

%ch% {0f}WdBoot:{#} 
sc query WdBoot >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}Не существует{#} ) else (
sc query WdBoot | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключен{#} ) ELSE (%ch% {04}Запущен{#} ))

%ch% {0f}WdFilter:{#} 
sc query WdFilter >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}Не существует{#} ) else (
sc query WdFilter | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключен{#} ) ELSE (%ch% {04}Запущен{#} ))

%ch% {0f}MsSecFlt:{#} 
sc query MsSecFlt >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}Не существует{#} ) else (
sc query MsSecFlt | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключен{#} ) ELSE (%ch% {04}Запущен{#} ))

%ch% {0f}SgrmAgent:{#} 
sc query SgrmAgent >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}Не существует{\n #}) else (
sc query SgrmAgent | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}Отключен{\n #}) ELSE (%ch% {04}Запущен{\n #}))

rem Проверка задач
set "taskpathDef1=Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
set "taskpathDef2=Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
set "taskpathDef3=Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
set "taskpathDef4=Microsoft\Windows\Windows Defender\Windows Defender Verification"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef1%" ') do set "replyTaskDef1=%%~I"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef2%" ') do set "replyTaskDef2=%%~I"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef3%" ') do set "replyTaskDef3=%%~I"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef4%" ') do set "replyTaskDef4=%%~I"
if not "!replyTaskDef1!"=="" (
	if "!replyTaskDef1!"=="Отключена" ( set "TaskDefResult1={0a}Отключена{#}" ) else ( set "TaskDefResult1={04}Включена{#}" )
) else ( set "TaskDefResult1={0a}Не существует{#}" )
if not "!replyTaskDef2!"=="" (
	if "!replyTaskDef2!"=="Отключена" ( set "TaskDefResult2={0a}Отключена{#}" ) else ( set "TaskDefResult2={04}Включена{#}" )
) else ( set "TaskDefResult2={0a}Не существует{#}" )
if not "!replyTaskDef3!"=="" (
	if "!replyTaskDef3!"=="Отключена" ( set "TaskDefResult3={0a}Отключена{#}" ) else ( set "TaskDefResult3={04}Включена{#}" )
) else ( set "TaskDefResult3={0a}Не существует{#}" )
if not "!replyTaskDef4!"=="" (
	if "!replyTaskDef4!"=="Отключена" ( set "TaskDefResult4={0a}Отключена{#}" ) else ( set "TaskDefResult4={04}Включена{#}" )
) else ( set "TaskDefResult4={0a}Не существует{#}" )

echo.
%ch% {03}Состояние задач в планировщике:{\n #}
%ch% {0f}Windows Defender Cache Maintenance: %TaskDefResult1%{\n #}
%ch% {0f}Windows Defender Cleanup:           %TaskDefResult2%{\n #}
%ch% {0f}Windows Defender Scheduled Scan:    %TaskDefResult3%{\n #}
%ch% {0f}Windows Defender Verification:      %TaskDefResult4%{\n #}

rem Задачи защитника
if not exist "%SYSTEMROOT%\System32\Tasks\Microsoft\Windows\Windows Defender" (
set "TasksDefender={0a}Папка удалена{#}"
) else (
set "TasksDefender={0c}Папка не удалена{#}"
)
%ch% {04}^--^>{#}{0f}Задачи (папка Tasks): %TasksDefender% {\n #}

echo.
%ch% {0f} 1{#} - {0a}Удаление защитника {08}[безвозвратно]{\n #}
if exist "%ProgramFiles%\Windows Defender" (
%ch% {0f} 2{#} - {0a}Отключение/включение {08}[в зависимости от состояния. требуется перезагрузка]{\n #}
) else (
%ch% {08} 2{#} - {08}Отключение/включение недоступно, защитник удален{\n #}
)
%ch% {0f} 3{#} - {0b}Удаление/Восстановление 'Безопасность Windows'{\n #}
%ch% {0f} 4{#} - {0e}Подробное состояние каталогов защитника{\n #}
%ch% {08} 5{#} - {08}ChangeLog{\n #}
%ch% {08} 6{#} - {08}Справка и разработчики{\n #}
%ch% {08} 7{#} - {08}Выход{\n #}
%ch%                                                                                                       {0b}By Vlado Для W10T{\n #}

echo.
set "input="
set /p input=*   Ваш выбор: 
if "%input%"=="1"    ( cls && goto DeleteDefender)
if "%input%"=="2"    ( cls && goto OnOffDefender)
if "%input%"=="3"    ( cls && goto SecHealth )
if "%input%"=="4"    ( cls && goto Catalogs)
if "%input%"=="5"    ( cls && goto ChangeLog )
if "%input%"=="6"    ( cls && goto Credits )
if "%input%"=="7"    ( exit )
) else (
	cls & goto Start
)

:DeleteDefender
rem Проверяем Unlocker
reg query "HKLM\SOFTWARE\Classes\CLSID\{DDE4BEEB-DDE6-48fd-8EB5-035C09923F83}" >nul 2>&1
if "%errorlevel%"=="0" (
%ch% {0c} У вас установлен Unlocker{\n #}
%ch% {0c} Удаление невозможно, поскольку возникает конфликт, временно удалите Unlocker и повторите попытку{\n #}
pause>nul && cls && goto Start
)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Unlocker.exe" >nul 2>&1
if "%errorlevel%"=="0" (
%ch% {0c} У вас установлен Unlocker{\n #}
%ch% {0c} Удаление невозможно, поскольку возникает конфликт, временно удалите Unlocker и повторите попытку{\n #}
pause>nul && cls && goto Start
)


sc query WinDefend >nul 2>&1
if ERRORLEVEL 1 (
%ch% {0c} Кажется, защитник уже удален. Вы хотите все равно провести удаление?{\n #}
%ch% {08} 1{#} - {0c}Да{\n #}
%ch% {08} 2{#} - {08}Отмена{\n #}
choice /c 12 /n /m " "
if ERRORLEVEL 2 cls && goto Start
)


rem Считаем место на диске перед удалением
setlocal enableextensions enabledelayedexpansion
for /f "usebackq tokens=2 delims==" %%i in (`wmic.exe LogicalDisk where "Name='c:'" get FreeSpace /value`) do set sFreeSize=%%i
if defined sFreeSize (set sFreeSizePseudoMb=%sFreeSize:~0,-7%)


cls

rem Поверх всех окон и отключаем окно
@cmdow @ /TOP
rem @cmdow @ /DIS

rem Завершаем процессы защитника
%ch%    {0f} Завершаем процессы защитника ...{\n #}
powershell -command "Stop-Process -processname MsMpEng, SecurityHealthSystray, SecurityHealthService, SecurityHealthHost, smartscreen, SgrmBroker, SecHealthUI, uhssvc, NisSrv -Force" >nul
taskkill /f /im MpCmdRun.exe >nul 2>&1
taskkill /f /im MsMpEng.exe >nul 2>&1
taskkill /f /im SecurityHealthSystray.exe >nul 2>&1
taskkill /f /im SecurityHealthService.exe >nul 2>&1
taskkill /f /im SecurityHealthHost.exe >nul 2>&1
taskkill /f /im smartscreen.exe >nul 2>&1
taskkill /f /im SgrmBroker.exe >nul 2>&1
taskkill /f /im SecHealthUI.exe >nul 2>&1
taskkill /f /im uhssvc.exe >nul 2>&1
taskkill /f /im NisSrv.exe >nul 2>&1

rem Обновляем иконки в трее
ConX.exe SysTrayRefresh
echo.


rem Отключение защитника и переименование smartscreen.exe
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t reg_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t reg_DWORD /d 0 /f >nul
ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen_fuck.exe" >nul 2>&1

if not exist "%SystemDrive%\Program Files\Windows Defender" (
%ch%    {0c} Пропустить удаление FuckDefender'ом ? {\n #}
%ch% {0f} 1 - Нет{\n #}
%ch% {0f} 2 - Да{\n #}
choice /c 12 /n /m " "
if ERRORLEVEL 2 goto NotFuckWD
)


rem Блок запуска FuckDefender
start FuckDefender.exe
:#
(
for /f %%i in ('"tasklist| findstr /bilc:"FuckDefender.exe""') do (%ch%    {04} Началось удаление.{\n #} && echo. && %ch% {0e}    Выполняется удаление ...{\n #})
)|| goto #

timeout /t 1 /nobreak >nul
echo.
%ch%    {0f} Немного ожидания ...{\n #}
timeout /t 1 /nobreak>nul
:reload
tasklist | find "FuckDefender.exe" >nul 2>&1
if ERRORLEVEL 1 goto NoRecord
goto reload
:NoRecord
>nul 2>&1 taskkill /f /im Unlocker.exe
>nul 2>&1 taskkill /f /im FuckDefender.exe
>nul 2>&1 taskkill /f /im wscript.exe


:NotFuckWD
echo.
%ch%    {0e} Удаляем службы Windows Defender ...{\n #}
sc delete SecurityHealthService >nul 2>&1
sc delete Sense >nul 2>&1
sc delete WdNisSvc >nul 2>&1
sc delete WinDefend >nul 2>&1
sc delete wscsvc >nul 2>&1
sc delete SgrmBroker >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\Sense /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\WinDefend /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\wscsvc /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker /f >nul 2>&1
echo.

%ch%    {0e} Удаляем задания из планировщика ...{\n #}
rd /s /q "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender" /f >nul 2>&1 
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f >nul 2>&1
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f >nul 2>&1
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f >nul 2>&1
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /f >nul 2>&1
echo.

%ch%    {0e} Отключаем драйвера Windows Defender ...{\n #}
sc stop WdNisDrv >nul 2>&1
sc stop WdBoot >nul 2>&1
sc stop WdFilter >nul 2>&1
sc stop MsSecFlt >nul 2>&1
sc stop SgrmAgent >nul 2>&1

reg add HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdBoot /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdFilter /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\MsSecFlt /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\SgrmAgent /v Start /t reg_DWORD /d 4 /f >nul
echo.

%ch%    {0e} Очищаем контекстное меню от Windows Defender ...{\n #}
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >nul 2>&1
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >nul 2>&1
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f >nul 2>&1
echo.

rem Удаляем все папки через CMD
%ch%    {0e} Удаляем папки и файлы Windows Defender ...{\n #}
RD /S /Q "%AllUsersProfile%\Microsoft\Windows Defender" >nul 2>&1
RD /S /Q "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" >nul 2>&1
RD /S /Q "%AllUsersProfile%\Microsoft\Windows Security Health" >nul 2>&1

RD /S /Q "%SystemDrive%\ProgramData\Microsoft\Windows Defender" >nul 2>&1
RD /S /Q "%SystemDrive%\ProgramData\Microsoft\Windows Security Health" >nul 2>&1

RD /S /Q "%SystemDrive%\Program Files\Windows Defender" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files\Windows Security" >nul 2>&1

RD /S /Q "%SystemDrive%\Program Files\PCHealthCheck" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files\Microsoft Update Health Tools" >nul 2>&1

RD /S /Q "%SystemDrive%\Program Files (x86)\Windows Defender" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files (x86)\Windows Defender Advanced Threat Protection" >nul 2>&1

RD /S /Q "%SystemRoot%\WinSxS\amd64_windows-defender-am-sigs_31bf3856ad364e35_10.0.19041.1_none_7275cb8fbafec5e1" >nul 2>&1

del /q /s "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" >nul 2>&1
del /q /s "%SystemRoot%\WinSxS\WindowsDefenderApplicationGuard.wim" >nul 2>&1
del /q "%SystemRoot%\security\database" >nul 2>&1

rem Удаление всех папок из WinSxS
rem For /F "usebackq delims=" %%d In (`2^>nul Dir "C:\Windows\WinSxS\*windows-defender*" /S /B /A:D`) Do Rd "%%d" /s /q


echo.
%ch%    {0a} Проходимся FuckDefender еще раз ...{\n #}
start FuckDefender.exe
:#1
(
for /f %%i in ('"tasklist| findstr /bilc:"FuckDefender.exe""') do (echo>nul)
)|| goto #1
:reload1
tasklist | find "FuckDefender.exe" >nul 2>&1
if ERRORLEVEL 1 goto NoRecord1
goto reload1
:NoRecord1
>nul 2>&1 taskkill /f /im Unlocker.exe
>nul 2>&1 taskkill /f /im FuckDefender.exe
>nul 2>&1 taskkill /f /im wscript.exe

wmic os get caption /Format:List | find /i "11" >nul 2>&1
if "%ERRORLEVEL%"=="0" (
echo.
%ch%    {0b} Delete Windows 11{\n #}
start /wait FuckDefender.exe
>nul 2>&1 taskkill /f /im Unlocker.exe
>nul 2>&1 taskkill /f /im FuckDefender.exe
>nul 2>&1 taskkill /f /im wscript.exe
)


rem Make window not always on top
@cmdow @ /NOT
rem @cmdow @ /ENA

rem Подсчет места на диске после удаления
for /f "usebackq tokens=2 delims==" %%i in (`wmic.exe LogicalDisk where "Name='c:'" get FreeSpace /value`) do set sFreeSize=%%i
if defined sFreeSize (set sFreeSizePseudoMb1=%sFreeSize:~0,-7%)
set /a Freed=!sFreeSizePseudoMb1! - !sFreeSizePseudoMb!
echo.
%ch%     {2f}!Freed! Мегабайт освобождено{\n #}
echo.
rem Проверяем удален ли защитник
if not exist "%ProgramFiles%\Windows Defender" (
powershell -command "[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::show('Защитник Windows удален из системы. Требуется перезагрузка ПК .', 'DefenderKiller By Vlado')" >nul
%ch%    {0c} Любая клавиша для выхода.{\n #}
pause>nul
exit
) else (
%ch%    {0c} Защитник не удален до конца. Повторите удаление еще раз.{\n #}
pause>nul && cls && goto Start
)


:OnOffDefender
if not exist "%ProgramFiles%\Windows Defender" (cls && goto Start)

sc query SecurityHealthService | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (
%ch% {0e} Включаем защитник ...{\n #}
echo.
timeout /t 1 /nobreak>nul
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t reg_DWORD /d "0x3" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t reg_DWORD /d "0x3" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t reg_DWORD /d "0x0" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t reg_DWORD /d "0x0" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t reg_DWORD /d "0x3" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t reg_DWORD /d "0x2" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t reg_DWORD /d "0x2" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "Start" /t reg_DWORD /d "0x2" /f >nul

reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >nul 2>&1

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /t reg_EXPAND_SZ /d "C:\Windows\system32\SecurityHealthSystray.exe" /f >nul

powershell -command "[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::show('Защитник Windows включен. Требуется перезагрузка ПК .', 'DefenderDisabler')" >nul
pause>nul && cls && goto Start
) else (
%ch% {0e} Отключаем защитник ...{\n #}
echo.
timeout /t 1 /nobreak>nul
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "Start" /t reg_DWORD /d "0x4" /f >nul


reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t reg_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t reg_DWORD /d 1 /f >nul

reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul 2>&1

powershell -command "[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::show('Защитник Windows отключен. Требуется перезагрузка ПК .', 'DefenderDisabler')" >nul
pause>nul && cls && goto Start
)


:Catalogs
%ch% {0e} C:\Program Files:{\n #}
if not exist "%SystemDrive%\Program Files\Windows Defender" (
%ch% {0f}C:\Program Files\Windows Defender {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files\Windows Defender {4f}НЕ УДАЛЕН{\n #}
)

if not exist "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" (
%ch% {0f}C:\Program Files\Windows Defender Advanced Threat Protection {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files\Windows Defender Advanced Threat Protection {04}НЕ УДАЛЕН{\n #}
)

if not exist "%SystemDrive%\Program Files\Windows Security" (
%ch% {0f}C:\Program Files\Windows Security {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files\Windows Security {04}НЕ УДАЛЕН{\n #}
)

if not exist "%SystemDrive%\Program Files\PCHealthCheck" (
%ch% {0f}C:\Program Files\PCHealthCheck {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files\PCHealthCheck {04}НЕ УДАЛЕН{\n #}
)

if not exist "%SystemDrive%\Program Files\Microsoft Update Health Tools" (
%ch% {0f}C:\Program Files\Microsoft Update Health Tools {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files\Microsoft Update Health Tools {04}НЕ УДАЛЕН{\n #}
)

echo.
%ch% {0e} C:\Program Files (^x86^):{\n #}
if not exist "%ProgramFiles(x86)%\Windows Defender" (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender {04}НЕ УДАЛЕН{\n #}
)

if not exist "%ProgramFiles(x86)%\Windows Defender Advanced Threat Protection" (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection {04}НЕ УДАЛЕН{\n #}
)

echo.
%ch% {0e} C:\ProgramData\Microsoft:{\n #}

if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender {04}НЕ УДАЛЕН{\n #}
)

if not exist "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection {04}НЕ УДАЛЕН{\n #}
)

if not exist "%AllUsersProfile%\Microsoft\Windows Security Health" (
%ch% {0f}C:\ProgramData\Microsoft\Windows Security Health {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\ProgramData\Microsoft\Windows Security Health {04}НЕ УДАЛЕН{\n #}
)
echo.

%ch% {0e} WindowsDefenderApplicationGuard.wim:{\n #}
if not exist "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" (
%ch% {0f}C:\Windows\Containers\WindowsDefenderApplicationGuard.wim {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Windows\Containers\WindowsDefenderApplicationGuard.wim {04}НЕ УДАЛЕН{\n #}
)

if not exist "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" (
%ch% {0f}C:\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim {0a}УДАЛЕН{\n #}
) else (
%ch% {0f}C:\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim {04}НЕ УДАЛЕН{\n #}
)

echo.
%ch% {08} Любая клавиша для возврата{\n #}
pause>nul && cls && goto Start


:ChangeLog
rem ChangeLog
%ch% {0c} v. 8 - 8.5{\n #}
echo 8.5
echo - Добавлена проверка перед запуском, чтобы "Защита в реальном времени" была отключена - без этого не скачается FuckDefender
echo --- теперь эта программа - один самостоятельных файл без зависимостей рядом (доступна также оффлайн версия)
echo --- добавлены описания к процессам
echo --- добавлена проверка на наличие защитника после удаления
echo --- правки интерфейса
echo --- добавлена проверка на наличие обновлений
echo -- добавлено удаление/восстановление приложения 'Безопасость Windows' (скрывает значок из меню пуск)
echo -- добавлена справка и разработчики
echo -- добавлена проверка на наличие установленного Unlocker'a в системе во-избежание конфликта удаления
echo - изменен шрифт, размер, прозрачность и цвет заголовка программы
%ch% {0c} v. 7 - 7.2{\n #}
echo - правки программы
%ch% {0c} v. 6 - 6.1{\n #}
echo -- добавлен процесс NisSrv - Microsoft Network Realtime Inspection Service
echo - правильное удаление WindowsDefenderApplicationGuard.wim
echo - добавлена возможность увидеть текущее состояние каталогов защитника
echo - добавлены каталоги для удаления для последних версий Windows 10 и 11
echo - добавлено более тщательное удаление задач из планировщика и отключение процессов
echo - изменены проверки на наличие защитника
%ch% {0c} v. 5.2{\n #}
echo - добавлено отключение/включение защитника без удаления. требуется перезагрузка пк
%ch% {0c} v. 5.1{\n #}
echo - номера версий программы изменены с 26 на "адекватные" , начиная с 1 версии
echo - исправлен баг интерфейса, возникающий из-за одновременного запуска твикера и программы
%ch% {0c} v. 5{\n #}
echo - небольшие правки интерфейса и скрытие названия окна приложения
echo - smartscreen теперь отключается и через реестр
echo - учтена ситуация, когда FuckWD задетектился антивирусами и удаление необходимо производить без него
%ch% {0c} v. 4{\n #}
echo - поправлен changelog
echo - добавлена проверка перед удалением на наличие защитника в системе и вывод соответствующего сообщения
echo - изменен размер главного окна, поскольку не весь текст вмещался
echo - добавлено удаление папки с задачами защитника
echo - обезврежен smartscreen
echo - добавлена проверка на состояние защитника и отключение защитника, если не отключен
%ch% {0c} v. 3{\n #}
echo - добавлен ChangeLog
echo - добавлена проверка, если установлена Windows 11 - проходим дополнительный раз FuckDefender
echo - добавлена проверка на права TI перед удалением
echo - небольшие правки интерфейса, кода и описаний функций
echo - изменен способ получения информации о запущенных процессах защитника
echo - удалены лишние переменные
%ch% {0c} v. 2{\n #}
echo - добавлены цвета
echo - изменен подход к получению административных прав при запуске, если включен UAC
%ch% {0c} v. 1{\n #}
echo - создание
echo.
%ch% {08} Любая клавиша для возврата{\n #}
pause>nul && cls && goto Start


:SecHealth
Set "UAC="
for /f "tokens=3" %%I in (' reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" 2^>nul ') do set /a "UAC=%%I"
if "%UAC%"=="1" (
%ch% {0c} У Вас включен UAC{\n #}
%ch% {0f} Для использования данной функции требуется, чтобы UAC был выключен{\n #} 
pause>nul && cls && goto Start)
ConX hide
NSudoLC.exe -U:C -wait SecHealth.bat
ConX Show
@cmdow @ /ACT
cls && goto Start


:Credits
%ch% {0E}DefenderKiller{\n #}
echo.
%ch% {0A}Данная утилита позволяет удалить защитник Windows {0c}безвозвратно. {08}[Не ломая никаких системных функций]{\n #}
echo.
%ch% {0b}Общий смысл:{\n #}
%ch% {0E}Естественно, говорить о том, что Ваш компьютер после удаления станет боингом и фпс взлетит на 100 кадров смысла нет.{\n #}
%ch% {0E}Однако, точно можно утверждать, что ПК избавится от лишних процессов защитника, занимающихся постоянным сканированием в фоне.{\n #}
%ch% {0E}Это позволит немного сократить потребление ОЗУ и снизить нагрузку на ЦП, что позитивно скажется на общем пользовании ПК{\n #}
echo.
%ch% {0b}Что удаляется и как это работает:{\n #}
%ch% {0E}Удаляются только каталоги (папки) защитника, не затрагивая никаких лишних папок. А также:{\n #}
%ch% {0E}Службы, задачи в планировщике, контекстное меню защитника, отключаются драйвера.{\n #}
%ch% {0E}Это никак не затрагивает других функций Windows{\n #}
%ch% {0E}После удаления необходимо перезагрузить ПК, чтобы все изменения вступили в силу{\n #}
echo.
%ch% {0b}Credits:{\n #}
%ch% {0f}Разработчик - Vlado{\n #}
%ch% {0f}Программа FuckWindowsDefender - XpucT{\n #}
%ch% {0f}Помощь в тестировании и улучшении программы - Flamer{\n #}
pause>nul && cls && goto Start


:CheckOff
Mode 90,15
Color 0f
echo Для того, чтобы защитник не удалил рабочие файлы программы, необходимо отключить
echo.
reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" || echo - Защиту в реальном времени
echo - Облачную защиту
echo - Автоматическую отправку образцов
echo - Защиту от подделки
start windowsdefender://threat
echo.
echo После отключения нажмите любую клавишу
pause>nul && cls && goto Start


:DownLoadFile
Color 04
ping www.google.nl -n 1 -w 1000 |>nul find /i "TTL=" || echo    Невозможно скачать требуемые файлы, нет интернет соединения. Программа не может работать без интернета. && pause && exit
md %SystemDrive%\DefenderKiller >nul 2>&1
cd /d "%SystemDrive%\DefenderKiller"
Mode 100,6
Color 0a
echo                                Интернет соединение установлено ...
echo.
echo                     Скачиваются необходимые файлы и идет проверка обновлений ...

curl -g -k -L -# -o "%tmp%\nircmd.zip" https://www.nirsoft.net/utils/nircmd-x64.zip >nul 2>&1
for /f %%i in ('dir/a-d/b "%tmp%\nircmd.zip"') do (
mshta "javascript:with(new ActiveXObject('Shell.Application')){nameSpace('C:\\DefenderKiller').copyHere(nameSpace('%tmp:\=\\%\\%%i').items(),5652)};close()"
del %tmp%\%%i
)
curl -g -k -L -# -o "%tmp%\nsudo.zip" https://github.com/M2Team/NSudo/releases/download/9.0-Preview1/NSudo_9.0_Preview1_9.0.2676.0.zip >nul 2>&1
for /f %%i in ('dir/a-d/b "%tmp%\nsudo.zip"') do (
mshta "javascript:with(new ActiveXObject('Shell.Application')){nameSpace('C:\\DefenderKiller').copyHere(nameSpace('%tmp:\=\\%\\%%i').items(),5652)};close()"
del %tmp%\%%i
)

curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\cecho.exe" "https://download1349.mediafire.com/1sj94et5bhtg/d6k2wex2qp2jqnp/cecho.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\SecHealth.bat" "https://download939.mediafire.com/34aryb1osfgg/lpo1b07wn628ck3/SecHealth.bat" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\TI.exe" "https://download1502.mediafire.com/g9otswtp7oig/njc4jepwlu4i9oo/TI.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\ConX.exe" "https://download1491.mediafire.com/42q5f5buw1ug/qxlplyx2nguf1p1/ConX.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\cmdow.exe" "https://raw.githubusercontent.com/ritchielawrence/cmdow/master/bin/Release/cmdow.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\FuckDefender.exe" "https://i.getspace.eu/cloud/s/N7PPHBiL2A4SDA6/download" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\TrInstaller.exe" https://github.com/mspaintmsi/superUser/releases/download/v4.0.0.1/superUser64.exe >nul 2>&1

pushd x64
copy NSudoLC.exe %SystemDrive%\DefenderKiller >nul
popd
rd /s /q ARM64 >nul 2>&1
rd /s /q Win32 >nul 2>&1
rd /s /q x64 >nul 2>&1
del /q People.txt >nul 2>&1
del /q nircmdc.exe >nul 2>&1
del /q NirCmd.chm >nul 2>&1
del /q License.txt >nul 2>&1
del /q MoPluginReadme.txt >nul 2>&1
del /q MoPluginReadme.zh-Hans.txt >nul 2>&1
goto:eof

:CheckUpdate
rem Version
set Version=8.3
curl -g -k -L -# -o "%temp%\latestVersion.bat" "https://pastebin.com/raw/dnENFgmC" >nul 2>&1
call "%temp%\latestVersion.bat"
if "%Version%" lss "!latestVersion!" (
@cmdow @ /SIZ 1000 250
cls
echo.
%ch%        {0c}Вы используете неактуальную версию DefenderKiller - {0e}!Version!, {0c}обновите программу перед использованием{\n #}
%ch%        {0f}Последняя актуальная версия - {0a}!latestVersion!{\n #}
%ch%        {0f}Вы хотите скачать последнюю актуальную версию?{\n #}
echo.
choice /c:"12" /n /m "[1] Да  [2] Нет, выйти"
if !errorlevel! equ 1 (
		curl -L -o %0 "https://github.com/VladoGold/DefenderKiller/releases/latest/download/DefenderKiller.bat" >nul 2>&1
		curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\SecHealth.bat" "https://github.com/VladoGold/DefenderKiller/raw/main/SecHealth.bat" >nul 2>&1
		call %0
		exit /b
		)
if !errorlevel! equ 2 ( exit )
)
goto:eof

:ModifedCMD
rem Делаем консоль прозрачной, изменяем ей шрифт и тд (делается под именем TI, поэтому, запустив реестр от имени обычного пользователя этой ветки вы не найдете)
rem 1 по умолчанию
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0x0" /f >nul
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "InsertMode" /t REG_DWORD /d "0x1" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "QuickEdit" /t REG_DWORD /d "0x1" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "ScreenBufferSize" /t REG_DWORD /d "0x23290078" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "WindowSize" /t REG_DWORD /d "0x1d0078" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FontSize" /t REG_DWORD /d "0xe0000" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FontFamily" /t REG_DWORD /d "0x36" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FontWeight" /t REG_DWORD /d "0x190" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FaceName" /t REG_SZ /d "Lucida Console" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "HistoryBufferSize" /t REG_DWORD /d "0x32" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "WindowAlpha" /t REG_DWORD /d "0xed" /f >nul 2>&1
TI.exe "%~f0" %* & exit