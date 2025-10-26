@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

NET SESSION >NUL 2>&1
IF ERRORLEVEL 1 (
	ECHO Please run this script with administrator privileges.
	PAUSE
	EXIT /B 1
)

SET BASE_KEY=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards

REM Delete all drivers previously installed.
FOR /F "tokens=*" %%A IN ('REG QUERY "%BASE_KEY%" 2^>NUL') DO (
	SET "INSTALLED_BY="
	FOR /F "tokens=2*" %%X IN ('REG QUERY "%%A" /V InstalledBy 2^>NUL') DO SET "INSTALLED_BY=%%Y"
	IF "!INSTALLED_BY!"=="gcc-win64" (
		ECHO Deleting path "%%A".
		REG DELETE "%%A" /F >NUL 2>&1
		IF ERRORLEVEL 1 (
			ECHO Failed to delete registry path "%%A".
		) ELSE (
			ECHO Successfully deleted registry path "%%A".
		)
	)
	ECHO.
)

ECHO Done.
PAUSE
EXIT /B 0
