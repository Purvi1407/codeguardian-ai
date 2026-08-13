from pydantic import BaseModel, Field
from typing import Optional, List


class ScanRequest(BaseModel):
    """Input for POST /scan, /analyze, and /validate. For the MVP we
    only support a public GitHub URL.

    The filter fields (Phase 6) are all optional and additive — omitting
    them returns everything, exactly as before this phase. When
    provided, filtering happens BEFORE AI validation on /validate
    specifically (not just on the final response), so a finding
    filtered out by severity/language/rule never costs an API call or a
    cache write — see README "Phase 6" design notes for why that
    ordering matters.
    """
    github_url: str = Field(..., description="Public GitHub repository URL, e.g. https://github.com/org/repo")
    branch: Optional[str] = Field(default=None, description="Branch to clone. Defaults to the repo's default branch.")
    severity_filter: Optional[List[str]] = Field(
        default=None, description="Only include findings with severity in this list, e.g. ['high', 'medium']"
    )
    language_filter: Optional[List[str]] = Field(
        default=None, description="Only include files/findings for these languages, e.g. ['Python']"
    )
    rule_filter: Optional[List[str]] = Field(
        default=None, description="Only include findings whose rule_id is in this list"
    )
    search: Optional[str] = Field(
        default=None,
        description="Case-insensitive substring search across file path, title, description, snippet, rule_id, and function name",
    )


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
