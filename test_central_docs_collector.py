# ===============================================================
# File Name: test_central_docs_collector.py
# Description:
#   central-docs-collector.py 에 대한 단위 및 통합 테스트 스위트
# ===============================================================
from __future__ import annotations

import ast
import importlib.util
import json
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

# 하이픈이 포함된 central-docs-collector.py 모듈 동적 로드
MODULE_PATH = Path(__file__).resolve().parent / "central-docs-collector.py"
spec = importlib.util.spec_from_file_location("central_docs_collector", MODULE_PATH)
assert spec is not None and spec.loader is not None
collector = importlib.util.module_from_spec(spec)
sys.modules["central_docs_collector"] = collector
spec.loader.exec_module(collector)


class TestSecurityAndExclusionFilters(unittest.TestCase):
    """시크릿/인증정보 차단 및 제외 디렉터리 필터 테스트"""

    def test_blocks_secret_and_sensitive_files(self) -> None:
        blocked_samples = [
            Path("/repo/.env"),
            Path("/repo/.env.local"),
            Path("/repo/.env.production"),
            Path("/repo/credentials.json"),
            Path("/repo/token.json"),
            Path("/Users/user/.claude/.claude.json"),
            Path("/Users/user/.gemini/antigravity-oauth-token"),
            Path("/Users/user/.gemini/jetski-standalone-oauth-token"),
            Path("/repo/certs/private.pem"),
            Path("/repo/certs/server.key"),
            Path("/Users/user/.claude/settings.json.bak.1791014467"),
            Path("/Users/user/.gemini/conversation_summaries.db"),
            Path("/Users/user/.gemini/conversation_summaries.db-wal"),
            Path("/repo/.DS_Store"),
        ]
        for p in blocked_samples:
            with self.subTest(path=p):
                self.assertTrue(collector.is_secret_or_blocked(p), f"Should block secret/cache file: {p}")

    def test_allows_safe_policy_and_history_files(self) -> None:
        allowed_samples = [
            Path("/repo/.env.example"),
            Path("/repo/SECURITY.md"),
            Path("/repo/.gitleaks.toml"),
            Path("/repo/CLAUDE.md"),
            Path("/Users/user/.claude/history.jsonl"),
            Path("/Users/user/.claude/settings.json"),
        ]
        for p in allowed_samples:
            with self.subTest(path=p):
                self.assertFalse(collector.is_secret_or_blocked(p), f"Should allow safe file: {p}")


class TestWorkspaceClassification(unittest.TestCase):
    """6대 엔지니어링·AI 관점별 파일 분류 테스트"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _touch(self, rel_path: str, content: str = "sample") -> Path:
        p = self.ws / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_classifies_decisions(self) -> None:
        p1 = self._touch("proj/backlog/decisions/decision-1 - 아키텍처-결정.md")
        p2 = self._touch("proj/backlog/config.yml")
        p3 = self._touch("proj/design/3-아키텍처-설계서/05-설계-결정.md")

        self.assertEqual(collector.classify_workspace_file(p1, self.ws), ("decision", "backlog-decision"))
        self.assertEqual(collector.classify_workspace_file(p2, self.ws), ("decision", "backlog-config"))
        self.assertEqual(collector.classify_workspace_file(p3, self.ws), ("decision", "architecture-decision"))

    def test_classifies_prompts(self) -> None:
        p1 = self._touch("tracer/PROMPT_SPEC.md")
        self.assertEqual(collector.classify_workspace_file(p1, self.ws), ("prompt", "prompt-spec"))

    def test_classifies_agents_and_rules(self) -> None:
        p1 = self._touch("proj/CLAUDE.md")
        p2 = self._touch("proj/GEMINI.md")
        p3 = self._touch("proj/AGENTS.md")
        p4 = self._touch("proj/.claude-code-agile-hooks.json")
        p5 = self._touch("proj/context/.cursorrules")

        self.assertEqual(collector.classify_workspace_file(p1, self.ws), ("agent", "agent-doc"))
        self.assertEqual(collector.classify_workspace_file(p2, self.ws), ("agent", "agent-doc"))
        self.assertEqual(collector.classify_workspace_file(p3, self.ws), ("agent", "agent-doc"))
        self.assertEqual(collector.classify_workspace_file(p4, self.ws), ("agent", "agent-config"))
        self.assertEqual(collector.classify_workspace_file(p5, self.ws), ("agent", "agent-config"))

    def test_classifies_skills_commands_and_hooks(self) -> None:
        p_cmd = self._touch("proj/.claude/commands/review-full.md")
        p_skl = self._touch("proj/.agents/skills/fuzzing/SKILL.md")
        p_hok = self._touch("proj/hooks/pre_commit_check.py")
        p_git_hok = self._touch("proj/template/hooks/prepare-commit-msg")
        # 프론트엔드 UI 훅이나 훅 테스트 파일은 제외되어야 함
        p_ui_hook = self._touch("proj/frontend/src/hooks/useAuth.ts")
        p_test_hook = self._touch("proj/hooks/test_pre_commit.py")

        self.assertEqual(collector.classify_workspace_file(p_cmd, self.ws), ("skill", "claude-command"))
        self.assertEqual(collector.classify_workspace_file(p_skl, self.ws), ("skill", "agent-skill"))
        self.assertEqual(collector.classify_workspace_file(p_hok, self.ws), ("skill", "project-hook"))
        self.assertEqual(collector.classify_workspace_file(p_git_hok, self.ws), ("skill", "project-hook"))
        self.assertIsNone(collector.classify_workspace_file(p_ui_hook, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_test_hook, self.ws))

    def test_classifies_design_and_ops_security(self) -> None:
        p_dsg = self._touch("proj/design/1-제안서/01-배경과-문제.md")
        p_dot = self._touch("proj/design/diagrams/01-arch.dot")
        p_str = self._touch("proj/PROJECT_STRUCTURE.md")
        p_sec = self._touch("proj/.gitleaks.toml")
        p_trv = self._touch("proj/.trivy.yaml")
        p_ci = self._touch("proj/.github/workflows/ci.yml")
        p_wf_lbl = self._touch("proj/.github/workflows/labeler.yml")
        p_dep = self._touch("proj/.github/dependabot.yml")

        self.assertEqual(collector.classify_workspace_file(p_dsg, self.ws), ("design", "design-doc"))
        self.assertEqual(collector.classify_workspace_file(p_dot, self.ws), ("design", "design-diagram-spec"))
        self.assertEqual(collector.classify_workspace_file(p_str, self.ws), ("design", "architecture-doc"))
        self.assertEqual(collector.classify_workspace_file(p_sec, self.ws), ("ops-sec", "security-policy"))
        self.assertEqual(collector.classify_workspace_file(p_trv, self.ws), ("ops-sec", "security-policy"))
        self.assertEqual(collector.classify_workspace_file(p_ci, self.ws), ("ops-sec", "ci-workflow"))
        self.assertEqual(collector.classify_workspace_file(p_wf_lbl, self.ws), ("ops-sec", "ci-workflow"))
        self.assertEqual(collector.classify_workspace_file(p_dep, self.ws), ("ops-sec", "repo-governance"))

    def test_excludes_worktrees_and_external_book_samples(self) -> None:
        p_wt = self._touch("factory/components/agent-orchestrator-wt/AO-6/backlog/decisions/decision-1.md")
        p_tlpi = self._touch("cpp/contents/linux/tlpi-dist/Makefile")
        p_ref = self._touch("tracer/references/ebpf-docs-master/hooks/doc.md")
        p_fzf = self._touch("fzf/.github/workflows/linux.yml")

        self.assertIsNone(collector.classify_workspace_file(p_wt, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_tlpi, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_ref, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_fzf, self.ws))


class TestFlatFilenameGeneration(unittest.TestCase):
    """단일 폴더 평탄화 파일명 규칙 및 macOS 255바이트 안전 축약 테스트"""

    def test_preserves_korean_decision_title_and_extension(self) -> None:
        rel = "coralstay-software-factory/backlog/decisions/decision-1 - Plan-Review-Go의-go는-서명-커밋으로-기록한다.md"
        flat = collector.build_flat_filename("decision", "workspace", rel)
        self.assertTrue(flat.startswith("decision__coralstay-software-factory__backlog__decisions__decision-1_-_"))
        self.assertTrue(flat.endswith(".md"))

    def test_shortens_only_synced_uuid_bucket_directory(self) -> None:
        bucket = "43068cff-771d-4338-ac61-ac783b509ced_6a4f3dc6-f857-42ce-a5b3-3715d0696d59"
        rel = f"~/.claude/skills/synced/{bucket}/deep-research/SKILL.md"
        flat = collector.build_flat_filename("skill", "global-claude", rel)
        self.assertEqual(flat, "skill__claude__skills__synced__43068cff__deep-research__SKILL.md")

    def test_shortens_36char_uuid_brain_directory(self) -> None:
        conv_uuid = "171950f4-7480-467c-8be3-5e728b51b1b6"
        rel = f"~/.gemini/antigravity/brain/{conv_uuid}/implementation_plan.md"
        flat = collector.build_flat_filename("agent", "global-antigravity", rel)
        self.assertEqual(flat, "agent__gemini__antigravity__brain__171950f4__implementation_plan.md")

    def test_truncates_utf8_bytes_safely_within_limit(self) -> None:
        long_title = "가나다라마바사아자차카타파하" * 10
        rel = f"project/backlog/decisions/decision-99 - {long_title}.md"
        flat = collector.build_flat_filename("decision", "workspace", rel, max_bytes=240)
        encoded = flat.encode("utf-8")
        self.assertLessEqual(len(encoded), 240)
        self.assertTrue(flat.endswith(".md"))
        self.assertIn("~", flat)


class TestPromptExtractionAndEndToEndCollection(unittest.TestCase):
    """Claude/Antigravity 프롬프트 추출 및 전체 수집 파이프라인 통합 테스트"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ws = self.root / "githubs"
        self.target = self.root / "central-docs"
        self.mock_claude = self.root / ".claude"
        self.mock_gemini = self.root / ".gemini"

        self.ws.mkdir(parents=True)
        self.mock_claude.mkdir(parents=True)
        self.mock_gemini.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_extracts_prompts_and_collects_all_into_sibling_target(self) -> None:
        # 1. 워크스페이스 샘플 파일 생성
        dec_file = self.ws / "my-proj" / "backlog" / "decisions" / "decision-1 - DB-선정.md"
        dec_file.parent.mkdir(parents=True)
        dec_file.write_text("# PostgreSQL 채택\n", encoding="utf-8")

        sec_file = self.ws / "my-proj" / ".gitleaks.toml"
        sec_file.write_text("[allowlist]\n", encoding="utf-8")

        secret_env = self.ws / "my-proj" / ".env"
        secret_env.write_text("DB_PASSWORD=supersecret\n", encoding="utf-8")

        # 2. 모의 Claude 히스토리 및 프로젝트 세션 트랜스크립트 생성
        claude_hist = self.mock_claude / "history.jsonl"
        claude_hist.write_text(
            json.dumps({
                "display": "첫 번째 클로드 프롬프트입니다",
                "timestamp": 1790000000000,
                "project": str(self.ws / "my-proj"),
                "sessionId": "sess-111",
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        proj_trans = self.mock_claude / "projects" / "my-proj" / "sess-222.jsonl"
        proj_trans.parent.mkdir(parents=True)
        proj_trans.write_text(
            "\n".join([
                json.dumps({
                    "type": "user",
                    "timestamp": "2026-10-20T10:00:00Z",
                    "cwd": str(self.ws / "my-proj"),
                    "sessionId": "sess-222",
                    "message": {"role": "user", "content": [{"type": "text", "text": "트랜스크립트 내부 프롬프트"}]},
                }, ensure_ascii=False),
                # tool_result 블록만 있는 이벤트는 프롬프트에서 제외되어야 함
                json.dumps({
                    "type": "user",
                    "timestamp": "2026-10-20T10:01:00Z",
                    "cwd": str(self.ws / "my-proj"),
                    "sessionId": "sess-222",
                    "message": {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]},
                }, ensure_ascii=False),
                # 서브에이전트 hand-back 메시지도 제외되어야 함
                json.dumps({
                    "type": "user",
                    "timestamp": "2026-10-20T10:02:00Z",
                    "cwd": str(self.ws / "my-proj"),
                    "sessionId": "sess-222",
                    "message": {"role": "user", "content": "<agent-message from=\"sub1\">hand-back</agent-message>"},
                }, ensure_ascii=False),
            ]) + "\n",
            encoding="utf-8",
        )
        # 서브에이전트 전용 트랜스크립트 파일(subagents/agent-*.jsonl)도 제외되어야 함
        subagent_trans = self.mock_claude / "projects" / "my-proj" / "sess-222" / "subagents" / "agent-abc.jsonl"
        subagent_trans.parent.mkdir(parents=True)
        subagent_trans.write_text(
            json.dumps({
                "type": "user",
                "timestamp": "2026-10-20T10:03:00Z",
                "cwd": str(self.ws / "my-proj"),
                "sessionId": "sess-222",
                "message": {"role": "user", "content": "You are implementing subagent task"},
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        # 3. 모의 Antigravity 브레인 트랜스크립트 및 1분 차이 중복 history.jsonl 생성
        agy_logs = self.mock_gemini / "antigravity-cli" / "brain" / "conv-333" / ".system_generated" / "logs"
        agy_logs.mkdir(parents=True)
        (agy_logs / "transcript.jsonl").write_text(
            json.dumps({
                "step_index": 0,
                "type": "USER_INPUT",
                "created_at": "2026-10-29T05:01:05Z",
                "content": "<USER_REQUEST>\n안티그래비티 프롬프트 테스트\n</USER_REQUEST>\n<ADDITIONAL_METADATA>meta</ADDITIONAL_METADATA>",
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        # 동일 프롬프트가 history.jsonl에 65초 전 타임스탬프로 기록되고, 단순 /usage 명령어도 섞여 있는 케이스
        agy_hist = self.mock_gemini / "antigravity-cli" / "history.jsonl"
        agy_hist.write_text(
            "\n".join([
                json.dumps({
                    "display": "안티그래비티 프롬프트 테스트",
                    "timestamp": "2026-10-29T05:00:00Z",
                    "workspace": str(self.ws),
                    "conversationId": "conv-333",
                }, ensure_ascii=False),
                json.dumps({
                    "display": "/usage",
                    "timestamp": "2026-10-29T05:02:00Z",
                    "workspace": str(self.ws),
                    "conversationId": "conv-333",
                }, ensure_ascii=False),
            ]) + "\n",
            encoding="utf-8",
        )

        with mock.patch.object(collector, "CLAUDE_HOME", self.mock_claude), \
             mock.patch.object(collector, "GEMINI_HOME", self.mock_gemini):
            items, prompt_count, index_path, manifest_path = collector.collect_all(
                workspace_root=self.ws,
                target_dir=self.target,
                include_global=True,
            )

        # 검증 1: 시크릿(.env)은 수집되지 않아야 함
        flat_names = {i.flat_filename for i in items}
        self.assertFalse(any(".env" in fn for fn in flat_names))

        # 검증 2: 의사결정 및 보안 설정 파일이 평탄하게 수집되어야 함
        self.assertIn("decision__my-proj__backlog__decisions__decision-1_-_DB-선정.md", flat_names)
        self.assertIn("ops-sec__my-proj__.gitleaks.toml", flat_names)

        # 검증 3: 3건의 인간 프롬프트만 정확히 추출되고 tool_result는 제외되어야 함
        self.assertEqual(prompt_count, 3)
        timeline_md = (self.target / "prompt__EXTRACTED__ALL_PROMPTS_TIMELINE.md").read_text(encoding="utf-8")
        self.assertIn("첫 번째 클로드 프롬프트입니다", timeline_md)
        self.assertIn("트랜스크립트 내부 프롬프트", timeline_md)
        self.assertIn("안티그래비티 프롬프트 테스트", timeline_md)

        # 검증 4: INDEX.md 와 MANIFEST.json 이 생성되고 원본 경로 매핑이 존재해야 함
        self.assertTrue(index_path.is_file())
        self.assertTrue(manifest_path.is_file())
        index_text = index_path.read_text(encoding="utf-8")
        # 공백이 포함된 원본 경로의 file:// 링크가 %20으로 안전하게 인코딩되어야 함
        self.assertIn("decision-1%20-%20DB-선정.md", index_text)
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest_data["extracted_prompt_count"], 3)
        self.assertEqual(manifest_data["total_count"], len(items))


class TestMarkdownAndTargetSafety(unittest.TestCase):
    """마크다운 코드블록 동적 펜스 및 타겟 디렉터리 안전 가드레일 테스트"""

    def test_wraps_nested_code_fence_dynamically(self) -> None:
        prompt_with_code = "아래 코드를 봐줘:\n```c\nint main() { return 0; }\n```"
        wrapped = collector._wrap_markdown_code_block(prompt_with_code, "text")
        self.assertEqual(wrapped[0], "````text")
        self.assertEqual(wrapped[2], "````")

    def test_rejects_dangerous_target_directories(self) -> None:
        ws = Path("/tmp/sample-ws/githubs")
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, ws)
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, ws.parent)
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, ws / "inside-ws-target")
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, Path.home())

    def test_normalizes_macos_nfd_hangul_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            nfd_rel = unicodedata.normalize("NFD", "proj/design/3-아키텍처-설계서/05-설계-결정.md")
            p = ws / nfd_rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# 결정\n", encoding="utf-8")
            self.assertEqual(collector.classify_workspace_file(p, ws), ("decision", "architecture-decision"))

    def test_documentation_tables_match_code_ast(self) -> None:
        src = MODULE_PATH.read_text(encoding="utf-8")
        header_comments = "\n".join(
            line for line in src.splitlines() if line.startswith("#")
        )
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                self.assertIn(
                    node.name,
                    header_comments,
                    f"Function/Class '{node.name}' missing from top-level documentation specification table",
                )
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.assertIn(
                    node.target.id,
                    header_comments,
                    f"Constant '{node.target.id}' missing from top-level documentation specification table",
                )


if __name__ == "__main__":
    unittest.main()
