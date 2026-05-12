@echo off
cd %~dp0
python -m uvicorn main:app --reload
