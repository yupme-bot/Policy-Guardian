@echo off
set BIN=dist\policyguardian.exe
if not exist %BIN% (echo Missing %BIN% & exit /b 4)
%BIN% policylock snapshot --created-at 2026-01-01T00:00:00Z --out demo_snapshot.zip fixtures\policylock\policy1.txt
if errorlevel 1 exit /b %ERRORLEVEL%
%BIN% consent record --subject "Alice@example.com" --tenant-salt 0011 --pepper aabb --created-at 2026-01-01T00:00:01Z --out demo_consent.json demo_snapshot.zip
if errorlevel 1 exit /b %ERRORLEVEL%
%BIN% policylock verify demo_snapshot.zip
if errorlevel 1 exit /b %ERRORLEVEL%
%BIN% consent verify --resolve-snapshot demo_consent.json
if errorlevel 1 exit /b %ERRORLEVEL%
echo DONE
