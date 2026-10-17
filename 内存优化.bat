@echo off

start "" /min """D:\PCL2.8.12\Plain Craft Launcher 2.exe"""

timeout /t 10 >nul

:loop
start "" """D:\PCL2.8.12\Plain Craft Launcher 2.exe""" --memory
timeout /t 250 >nul
goto loop
