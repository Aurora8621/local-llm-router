# ============================================================
#  start_gui.ps1 — 一键启动本地多模型免费额度调度器 GUI（网页版）
#  用法：双击本文件，或在 PowerShell 中执行：
#        powershell -ExecutionPolicy Bypass -File F:\AI\local-llm-router\start_gui.ps1
#  说明：自动激活 conda workenv 环境，浏览器打开 http://127.0.0.1:7860
#        关闭方法：回到本窗口按 Ctrl+C
# ============================================================

$ErrorActionPreference = 'Stop'

$ProjectDir = 'F:\AI\local-llm-router'
$CondaHook  = 'C:\Users\YourName\miniconda3\shell\condabin\conda-hook.ps1'
$WorkenvPy  = 'C:\Users\YourName\miniconda3\envs\workenv\python.exe'

function Show-Title {
    Write-Host ''
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host '   本地多模型免费额度调度器（网页版）' -ForegroundColor Cyan
    Write-Host '   http://127.0.0.1:7860  仅本机可访问' -ForegroundColor Gray
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host ''
}

Set-Location $ProjectDir

$launched = $false

# 方案A：通过 conda hook 激活 workenv 后启动（解释器固定用完整路径，避免激活不彻底串到 base）
if (Test-Path $CondaHook) {
    try {
        & $CondaHook
        conda activate workenv
        Show-Title
        Write-Host '正在启动 GUI（conda workenv）...' -ForegroundColor Green
        & $WorkenvPy -X utf8 -u "$ProjectDir\gui.py"
        $launched = $true
    }
    catch {
        Write-Host "conda 初始化失败，改用完整路径启动：$($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# 方案B：回退——直接用 workenv 的 Python 完整路径启动
if (-not $launched) {
    if (-not (Test-Path $WorkenvPy)) {
        Write-Host '' -ForegroundColor Red
        Write-Host "错误：找不到 workenv 的 Python（$WorkenvPy）。" -ForegroundColor Red
        Write-Host '请确认 Miniconda 安装位置，或修改本脚本顶部的路径。' -ForegroundColor Red
        Read-Host '按回车退出'
        exit 1
    }
    Show-Title
    Write-Host '正在启动 GUI（完整路径）...' -ForegroundColor Green
    & $WorkenvPy -X utf8 -u "$ProjectDir\gui.py"
}

Write-Host ''
Write-Host 'GUI 已退出。' -ForegroundColor Gray
Read-Host '按回车关闭窗口...'
