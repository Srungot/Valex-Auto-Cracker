@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

NET SESSION >NUL 2>&1
IF ERRORLEVEL 1 (
	ECHO Please run this script with administrator privileges.
	PAUSE
	EXIT /B 1
)

SET BASE_KEY=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards
FOR %%A IN ("%~dp0\..\..\bin") DO SET "DRIVER_DIR=%%~fA"
SET COUNT=-1

IF NOT EXIST "%DRIVER_DIR%\opensc-minidriver.dll" (
	ECHO Could not find driver in "%DRIVER_DIR%\opensc-minidriver.dll".
	PAUSE
	EXIT /B 1
)

SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=ePass2003
SET      ATR[%COUNT%]=3b,9f,95,81,31,fe,9f,00,66,46,53,05,00,00,00,71,df,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,ff,ff,ff,ff,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=FTCOS/PK-01C
SET      ATR[%COUNT%]=3b,9f,95,81,31,fe,9f,00,65,46,53,05,00,06,71,df,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,ff,ff,ff,ff,ff,ff,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=SmartCard-HSM
SET      ATR[%COUNT%]=3b,fe,18,00,00,81,31,fe,45,80,31,81,54,48,53,4d,31,73,80,21,40,81,07,fa
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=SmartCard-HSM-CL
SET      ATR[%COUNT%]=3b,8e,80,01,80,31,81,54,48,53,4d,31,73,80,21,40,81,07,18
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=SmartCard-HSM 4K
SET      ATR[%COUNT%]=3b,de,00,ff,81,91,fe,1f,c3,80,31,81,54,48,53,4d,31,73,80,21,40,81,07,00
SET ATR_MASK[%COUNT%]=ff,ff,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Contactless Smart Card
SET      ATR[%COUNT%]=3b,80,80,01,01
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID
SET      ATR[%COUNT%]=3b,84,80,01,47,6f,49,44,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (01)
SET      ATR[%COUNT%]=3b,85,80,01,47,6f,49,44,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (02)
SET      ATR[%COUNT%]=3b,86,80,01,47,6f,49,44,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (03)
SET      ATR[%COUNT%]=3b,87,80,01,47,6f,49,44,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (04)
SET      ATR[%COUNT%]=3b,88,80,01,47,6f,49,44,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (05)
SET      ATR[%COUNT%]=3b,89,80,01,47,6f,49,44,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (06)
SET      ATR[%COUNT%]=3b,8a,80,01,47,6f,49,44,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (07)
SET      ATR[%COUNT%]=3b,8b,80,01,47,6f,49,44,00,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (08)
SET      ATR[%COUNT%]=3b,8c,80,01,47,6f,49,44,00,00,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (09)
SET      ATR[%COUNT%]=3b,8d,80,01,47,6f,49,44,00,00,00,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (10)
SET      ATR[%COUNT%]=3b,8e,80,01,47,6f,49,44,00,00,00,00,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=GoID (11)
SET      ATR[%COUNT%]=3b,8f,80,01,47,6f,49,44,00,00,00,00,00,00,00,00,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CEV WESTCOS
SET      ATR[%COUNT%]=3f,69,00,00,00,64,01,00,00,00,80,90,00
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,00,00,00,f0,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=OpenPGP card v1.x
SET      ATR[%COUNT%]=3b,fa,13,00,ff,81,31,80,45,00,31,c1,73,c0,01,00,00,90,00,b1
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=OpenPGP card v2.x
SET      ATR[%COUNT%]=3b,da,18,ff,81,b1,fe,75,1f,03,00,31,c5,73,c0,01,40,00,90,00,0c
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Gnuk v1.0.x (OpenPGP v2.0)
SET      ATR[%COUNT%]=3b,da,11,ff,81,b1,fe,55,1f,03,00,31,84,73,80,01,80,00,90,00,e4
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,ff,ff,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=OpenPGP card v3.x
SET      ATR[%COUNT%]=3b,da,18,ff,81,b1,fe,75,1f,03,00,31,f5,73,c0,01,60,00,90,00,1c
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=MaskTech smart card (a)
SET      ATR[%COUNT%]=3b,89,80,01,4d,54,43,4f,53,70,02,00,04,31
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,fc,ff,fc,f4,f5
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=MaskTech smart card (b)
SET      ATR[%COUNT%]=3b,9d,13,81,31,60,35,80,31,c0,69,4d,54,43,4f,53,73,02,00,00,40
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,fd,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fc,f0,f0
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=MaskTech smart card (c)
SET      ATR[%COUNT%]=3b,88,80,01,00,00,00,00,77,81,80,00,6e
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ee,ff,ee
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS 4.0
SET      ATR[%COUNT%]=3b,e2,00,ff,c1,10,31,fe,55,c8,02,9c
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS 4.2+
SET      ATR[%COUNT%]=3b,f2,08,00,00,c1,00,31,fe,00,00,00,00
SET ATR_MASK[%COUNT%]=ff,ff,0f,ff,00,ff,00,ff,ff,00,00,00,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Italian CNS (a)
SET      ATR[%COUNT%]=3b,e9,00,ff,c1,10,31,fe,55,00,64,05,00,c8,02,31,80,00,47
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Italian CNS (b)
SET      ATR[%COUNT%]=3b,fb,98,00,ff,c1,10,31,fe,55,00,64,05,20,47,03,31,80,00,90,00,f3
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Italian CNS (c)
SET      ATR[%COUNT%]=3b,fc,98,00,ff,c1,10,31,fe,55,c8,03,49,6e,66,6f,63,61,6d,65,72,65,28
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Italian CNS (d)
SET      ATR[%COUNT%]=3b,ff,18,00,ff,81,31,fe,55,00,6b,02,09,03,03,01,01,01,43,4e,53,10,31,80,9d
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Italian CNS (e)
SET      ATR[%COUNT%]=3b,ff,18,00,00,81,31,fe,45,00,6b,11,05,07,00,01,21,01,43,4e,53,10,31,80,4a
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS 4.0 a
SET      ATR[%COUNT%]=3b,f4,98,00,ff,c1,10,31,fe,55,4d,34,63,76,b4
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Cardos M4
SET      ATR[%COUNT%]=3b,f2,18,00,02,c1,0a,31,fe,58,c8,08,74
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS 4.4
SET      ATR[%COUNT%]=3b,d2,18,02,c1,0a,31,fe,58,c8,0d,51
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS v5.0 (a)
SET      ATR[%COUNT%]=3b,d2,18,00,81,31,fe,58,c9,01,14
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS v5.3 (b)
SET      ATR[%COUNT%]=3b,d2,18,00,81,31,fe,58,c9,02,17
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS v5.3 (c)
SET      ATR[%COUNT%]=3b,d2,18,00,81,31,fe,58,c9,03,16
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=CardOS v5.4
SET      ATR[%COUNT%]=3b,d2,18,00,81,31,fe,58,c9,04,11
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=JPKI
SET      ATR[%COUNT%]=3b,e0,00,ff,81,31,fe,45,14
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS (a)
SET      ATR[%COUNT%]=3b,b7,94,00,c0,24,31,fe,65,53,50,4b,32,33,90,00,b4
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS (b)
SET      ATR[%COUNT%]=3b,b7,94,00,81,31,fe,65,53,50,4b,32,33,90,00,d1
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS (c)
SET      ATR[%COUNT%]=3b,b7,18,00,c0,3e,31,fe,65,53,50,4b,32,34,90,00,25
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.4
SET      ATR[%COUNT%]=3b,d8,18,ff,81,b1,fe,45,1f,03,80,64,04,1a,b4,03,81,05,61
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.5 (a)
SET      ATR[%COUNT%]=3b,9b,96,c0,0a,31,fe,45,80,67,04,1e,b5,01,00,89,4c,81,05,45
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.5 (b)
SET      ATR[%COUNT%]=3b,db,96,ff,81,31,fe,45,80,67,05,34,b5,02,01,c0,a1,81,05,3c
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.5 (c)
SET      ATR[%COUNT%]=3b,d9,96,ff,81,31,fe,45,80,31,b8,73,86,01,c0,81,05,02
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.5 (d)
SET      ATR[%COUNT%]=3b,df,96,ff,81,31,fe,45,80,5b,44,45,2e,42,4e,4f,54,4b,31,31,31,81,05,a0
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.5 (e)
SET      ATR[%COUNT%]=3b,df,96,ff,81,31,fe,45,80,5b,44,45,2e,42,4e,4f,54,4b,31,30,30,81,05,a0
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=STARCOS 3.5 (f)
SET      ATR[%COUNT%]=3b,d9,96,ff,81,31,fe,45,80,31,b8,73,86,01,e0,81,05,22
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Rutoken ECP
SET      ATR[%COUNT%]=3b,8b,01,52,75,74,6f,6b,65,6e,20,45,43,50,a0
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Rutoken ECP (DS)
SET      ATR[%COUNT%]=3b,8b,01,52,75,74,6f,6b,65,6e,20,44,53,20,c1
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Rutoken ECP SC
SET      ATR[%COUNT%]=3b,9c,96,00,52,75,74,6f,6b,65,6e,45,43,50,73,63
SET ATR_MASK[%COUNT%]=00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Rutoken ECP SC
SET      ATR[%COUNT%]=3b,9c,94,80,11,40,52,75,74,6f,6b,65,6e,45,43,50,73,63,c3
SET ATR_MASK[%COUNT%]=00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Rutoken Lite
SET      ATR[%COUNT%]=3b,8b,01,52,75,74,6f,6b,65,6e,6c,69,74,65,c2
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Rutoken Lite SC
SET      ATR[%COUNT%]=3b,8b,01,52,75,74,6f,6b,65,6e,6c,69,74,65,c2
SET ATR_MASK[%COUNT%]=00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=IAS/ECC CPx
SET      ATR[%COUNT%]=3b,00,00,00,00,00,12,25,00,64,80,00,00,00,00,90,00
SET ATR_MASK[%COUNT%]=ff,00,00,00,00,ff,ff,ff,ff,ff,ff,00,00,00,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=IAS/ECC CPxCL
SET      ATR[%COUNT%]=3b,8f,80,01,00,31,b8,64,00,00,ec,c0,73,94,01,80,82,90,00,0e
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,00,00,ff,c0,ff,ff,ff,ff,ff,ff,ff,ff
SET /A COUNT+=1
SET  SC_NAME[%COUNT%]=Swissbit iShield Key Pro
SET      ATR[%COUNT%]=3b,97,11,81,21,75,69,53,68,69,65,6c,64,05
SET ATR_MASK[%COUNT%]=ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff

REM Loop through the registration data and add registry entries.
FOR /L %%i IN (0,1,%COUNT%) DO (
	SET "INSTALLED_BY="
	FOR /F "tokens=2*" %%A IN ('REG QUERY "%BASE_KEY%\!SC_NAME[%%i]!" /V InstalledBy 2^>NUL') DO SET "INSTALLED_BY=%%B"
	REG QUERY "%BASE_KEY%\!SC_NAME[%%i]!" >NUL 2>&1
	IF ERRORLEVEL 1 SET "INSTALLED_BY=gcc-win64"
	IF "!INSTALLED_BY!"=="gcc-win64" (
		ECHO Adding entry for "!SC_NAME[%%i]!".
		SET "SUB_KEY=%BASE_KEY%\!SC_NAME[%%i]!"

		ECHO Windows Registry Editor Version 5.00 > "%TEMP%\install-opensc-minidriver.reg"
		ECHO. >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO [!SUB_KEY!] >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO "ATR"=hex:!ATR[%%i]! >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO "ATRMask"=hex:!ATR_MASK[%%i]! >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO "Crypto Provider"="Microsoft Base Smart Card Crypto Provider" >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO "80000001"="%DRIVER_DIR%\opensc-minidriver.dll" >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO "Smart Card Key Storage Provider"="Microsoft Smart Card Key Storage Provider" >> "%TEMP%\install-opensc-minidriver.reg"
		ECHO "InstalledBy"="gcc-win64" >> "%TEMP%\install-opensc-minidriver.reg"

		REG IMPORT "%TEMP%\install-opensc-minidriver.reg" >NUL 2>&1
		IF ERRORLEVEL 1 (
			ECHO Failed to add registry entry for "!SC_NAME[%%i]!".
		) ELSE (
			ECHO Successfully added registry entry for "!SC_NAME[%%i]!".
		)
		ECHO.
	)
)
DEL /F /Q "%TEMP%\install-opensc-minidriver.reg"

ECHO Done.
PAUSE
EXIT /B 0
