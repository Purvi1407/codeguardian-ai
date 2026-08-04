FROM python:3.11-slim

# git is a runtime dependency, not a dev convenience — repo_processor.py
# shells out to `git clone` on every /scan, /analyze, /validate request.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first so this layer is cached across code-only changes.
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy the backend/ folder as-is, preserving backend/app/core/config.py's
# nesting. config.py computes BASE_DIR as parent^4 of its own __file__:
#   config.py -> core -> app -> backend -> BASE_DIR
# so BASE_DIR lands at /app regardless of what sits above backend/ on the
# host — the fix is "keep this exact folder shape," not "flatten it."
COPY backend/ backend/

WORKDIR /app/backend

# Render (and most PaaS platforms) inject $PORT at runtime; the app must
# bind to it, not to a hardcoded 8000. Shell form so $PORT expands.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
