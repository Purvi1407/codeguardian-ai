from pydantic import BaseModel, Field
from typing import Optional, List


class ScanRequest(BaseModel):
    """Input for POST /scan. For the MVP we only support a public GitHub URL."""
    github_url: str = Field(..., description="Public GitHub repository URL, e.g. https://github.com/org/repo")
    branch: Optional[str] = Field(default=None, description="Branch to clone. Defaults to the repo's default branch.")


class FunctionInfo(BaseModel):
    name: str
    start_line: int
    end_line: int
    args: List[str] = []
    is_method: bool = False
    parent_class: Optional[str] = None


class ClassInfo(BaseModel):
    name: str
    start_line: int
    end_line: int
    methods: List[str] = []


class FileMetadata(BaseModel):
    path: str  # relative path within the repo
    language: str
    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []
    loc: int = 0
    parse_error: Optional[str] = None  # populated if we found the file but couldn't parse it


class ScanResponse(BaseModel):
    repository: str
    branch: str
    languages: List[str]
    file_count: int
    files: List[FileMetadata]
