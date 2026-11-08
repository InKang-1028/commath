# 가상환경(.venv) 활성화. 처음 실행하면 만들고 pycryptodome도 설치한다.
# 사용법 (project_1 폴더에서):  source venv.sh
#   ※ "bash venv.sh"로 실행하면 활성화가 유지되지 않으니 꼭 source로 실행
#   비활성화: deactivate

VENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[venv] $VENV_DIR 생성 중..."
    python3 -m venv "$VENV_DIR" || return 1
fi

if [ -f "$VENV_DIR/bin/activate" ]; then
    . "$VENV_DIR/bin/activate"              # Linux / macOS
else
    . "$VENV_DIR/Scripts/activate"          # Windows (Git Bash)
fi

if ! python -c "import Crypto" 2>/dev/null; then
    echo "[venv] pycryptodome 설치 중..."
    pip install -q pycryptodome
fi

echo "[venv] 활성화 완료: $(python --version), $(which python)"
