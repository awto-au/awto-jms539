import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import ghidra_8051 as pipeline


class GhidraPipelineGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix=".test-ghidra-8051-", dir=pipeline.ANALYSIS_ROOT
        )
        self.workspace = Path(self.temporary_directory.name) / "workspace"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_minimal_exports(
        self,
        directory: Path,
        version: str,
        mapped_sha256: str,
        instruction_header: str = (
            "address\tcontaining_function_entry\tbytes\tmnemonic\toperands\t"
            "user_label\tplate_comment"
        ),
        function_header: str = (
            "entry\tname\tbody_start\tbody_end\tbody_ranges\tname_status\tcomment"
        ),
    ) -> None:
        (directory / "program.tsv").write_text(
            "key\tvalue\n"
            f"processor_language\t{pipeline.LANGUAGE_ID}\n"
            f"compiler_spec\t{pipeline.COMPILER_SPEC_ID}\n"
            "expected_cpu_range\t0x4000..0xFFFF\n"
            f"mapped_image_sha256\t{mapped_sha256}\n"
            f"mapped_image_bytes_verified\t{pipeline.IMAGE_LENGTH}\n\n",
            encoding="utf-8",
        )
        (directory / "instructions.tsv").write_text(
            instruction_header + "\n0x4000\tfixture\n", encoding="utf-8"
        )
        (directory / "functions.tsv").write_text(
            function_header + "\n0x4000\tfixture\n", encoding="utf-8"
        )
        summary = (
            "key\tvalue\n"
            f"firmware_version\t{version}\n"
            f"language_id\t{pipeline.LANGUAGE_ID}\n"
            f"compiler_spec_id\t{pipeline.COMPILER_SPEC_ID}\n"
            "image_range\t0x4000..0xFFFF\n"
            f"mapped_image_sha256\t{mapped_sha256}\n"
            f"mapped_image_bytes_verified\t{pipeline.IMAGE_LENGTH}\n"
            "instruction_count\t1\n"
            "function_count\t1\n"
        )
        (directory / "summary.tsv").write_text(summary, encoding="utf-8")
        for name in (
            "data.tsv",
            "calls.tsv",
            "references.tsv",
            "decompilation.c",
            "findings.tsv",
        ):
            (directory / name).write_text("placeholder\n", encoding="utf-8")

    def run_fake_export(self, workspace: Path, expected_sha256: str):
        return pipeline.run_staged_export(
            "40.06",
            expected_sha256,
            "f" * 64,
            workspace,
            "unused-analyzeHeadless",
            lambda stage: ["fake-ghidra", str(stage)],
        )

    def test_workspace_must_be_a_dedicated_subdirectory_of_analysis_initial(self):
        with self.assertRaisesRegex(pipeline.PipelineError, "confined under"):
            pipeline.resolve_workspace(ROOT)

    def test_import_refuses_existing_project_artifacts_without_running_ghidra(self):
        for suffix in (".gpr", ".rep"):
            with self.subTest(suffix=suffix):
                workspace = self.workspace / f"existing{suffix}"
                project_dir = pipeline.project_directory(workspace)
                project_dir.mkdir(parents=True)
                artifact = project_dir / f"{pipeline.project_name('40.06')}{suffix}"
                if suffix == ".rep":
                    artifact.mkdir()
                else:
                    artifact.write_text("existing annotation-bearing project\n")

                with (
                    mock.patch.object(pipeline, "run_headless") as run_headless,
                    self.assertRaisesRegex(
                        pipeline.PipelineError, "Refusing to overwrite"
                    ),
                ):
                    pipeline.import_version(
                        "40.06", "unused-analyzeHeadless", workspace
                    )
                run_headless.assert_not_called()

    def test_exporter_receives_expected_sha256_without_overwrite_flag(self):
        expected = "a" * 64
        stage = self.workspace / "stage"
        args = pipeline.export_script_arguments("40.06", expected, stage)
        self.assertEqual(
            args,
            [
                "-postScript",
                "ExportJms5398051.java",
                "40.06",
                expected,
                str(stage),
            ],
        )
        command = pipeline.build_regen_command(
            "40.06", self.workspace, expected, "f" * 64, stage
        )
        self.assertNotIn("-overwrite", command)
        self.assertIn(expected, command)
        import_command = pipeline.build_import_command(
            "40.06", self.workspace, expected, "f" * 64, stage
        )
        self.assertNotIn("-overwrite", import_command)

    def test_incomplete_fresh_stage_does_not_replace_previous_exports(self):
        expected = "b" * 64
        destination = pipeline.export_path("40.06", self.workspace)
        destination.mkdir(parents=True)
        previous = destination / "summary.tsv"
        previous.write_text("previous validated output\n", encoding="utf-8")

        def produce_partial_export(command, _headless, _workspace):
            stage = Path(command[-1])
            (stage / "program.tsv").write_text(
                "partial output only\n", encoding="utf-8"
            )

        with (
            mock.patch.object(
                pipeline, "run_headless", side_effect=produce_partial_export
            ),
            self.assertRaisesRegex(pipeline.PipelineError, "incomplete or empty"),
        ):
            self.run_fake_export(self.workspace, expected)

        self.assertEqual(
            previous.read_text(encoding="utf-8"), "previous validated output\n"
        )
        self.assertEqual(list(destination.parent.glob(".stage-40-06-*")), [])

    def test_mismatched_mapped_hash_is_rejected_before_publication(self):
        expected = "c" * 64
        incorrect = "d" * 64
        destination = pipeline.export_path("40.06", self.workspace)
        destination.mkdir(parents=True)
        previous = destination / "summary.tsv"
        previous.write_text("preserve this export\n", encoding="utf-8")

        def produce_wrong_hash(command, _headless, _workspace):
            stage = Path(command[-1])
            self.write_minimal_exports(stage, "40.06", incorrect)

        with (
            mock.patch.object(pipeline, "run_headless", side_effect=produce_wrong_hash),
            self.assertRaisesRegex(
                pipeline.PipelineError, "mapped-image SHA-256 mismatch"
            ),
        ):
            self.run_fake_export(self.workspace, expected)

        self.assertEqual(previous.read_text(encoding="utf-8"), "preserve this export\n")

    def test_single_version_does_not_compare_or_require_the_sibling(self):
        with (
            mock.patch.object(pipeline, "require_project_absent"),
            mock.patch.object(pipeline, "resolve_headless", return_value="ghidra"),
            mock.patch.object(pipeline, "import_version") as run_import,
            mock.patch.object(pipeline, "compare_siblings") as compare,
        ):
            result = pipeline.main(
                ["import", "--version", "40.06", "--workspace", str(self.workspace)]
            )
        self.assertEqual(result, 0)
        run_import.assert_called_once_with("40.06", "ghidra", self.workspace)
        compare.assert_not_called()

    def test_findings_must_be_bound_to_the_input_image(self):
        findings_dir = self.workspace / "findings"
        findings_dir.mkdir(parents=True)
        path = findings_dir / "ghidra_names_40.06.tsv"
        path.write_text("# image_sha256=" + "a" * 64 + "\n", encoding="utf-8")
        with (
            mock.patch.object(pipeline, "FINDINGS_DIR", findings_dir),
            self.assertRaisesRegex(pipeline.PipelineError, "does not match"),
        ):
            pipeline.read_verified_findings("40.06", "b" * 64)

    def test_export_publication_does_not_delete_unexpected_files(self):
        destination = self.workspace / "exports" / "40.06"
        destination.mkdir(parents=True)
        notes = destination / "user-notes.txt"
        notes.write_text("keep this\n", encoding="utf-8")
        stage = self.workspace / "stage"
        stage.mkdir()
        with self.assertRaisesRegex(pipeline.PipelineError, "unexpected files"):
            pipeline.publish_staged_directory(stage, destination)
        self.assertEqual(notes.read_text(encoding="utf-8"), "keep this\n")
        self.assertTrue(stage.is_dir())

    def test_findings_export_marks_guesses_as_candidates(self):
        findings_dir = self.workspace / "findings"
        findings_dir.mkdir(parents=True)
        source = findings_dir / "ghidra_names_40.06.tsv"
        image_sha = "a" * 64
        source.write_text(
            "# image_sha256=" + image_sha + "\n"
            "CODE:4000\tmaybe\tfunc\tunknown\t[guess]\tmed\n",
            encoding="utf-8",
        )
        stage = self.workspace / "stage"
        stage.mkdir()
        (stage / "findings.tsv").write_text(
            "address\tname\ttype\tcomment\tstatus\tconfidence\tapplication\n"
            "CODE:4000\tmaybe\tfunc\tunknown\t[guess]\tmed\tapplied\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(pipeline, "FINDINGS_DIR", findings_dir),
            self.assertRaisesRegex(pipeline.PipelineError, "do not match"),
        ):
            pipeline.validate_findings_export(
                "40.06", stage, image_sha, pipeline.sha256(source.read_bytes())
            )

    def test_findings_export_accepts_lowercase_addresses_and_crlf(self):
        findings_dir = self.workspace / "findings"
        findings_dir.mkdir(parents=True)
        source = findings_dir / "ghidra_names_40.06.tsv"
        image_sha = "a" * 64
        source.write_bytes(
            (
                f"# image_sha256={image_sha}\r\n"
                "CODE:abce\tmaybe\tlabel\tunknown\t[guess]\tmed\r\n"
            ).encode()
        )
        stage = self.workspace / "stage"
        stage.mkdir()
        (stage / "findings.tsv").write_text(
            "address\tname\ttype\tcomment\tstatus\tconfidence\tapplication\n"
            "CODE:ABCE\tmaybe\tlabel\tunknown\t[guess]\tmed\tcandidate\n",
            encoding="utf-8",
        )
        with mock.patch.object(pipeline, "FINDINGS_DIR", findings_dir):
            pipeline.validate_findings_export(
                "40.06", stage, image_sha, pipeline.sha256(source.read_bytes())
            )

    def test_sibling_matching_columns_are_required_in_staged_exports(self):
        expected = "e" * 64
        destination = pipeline.export_path("40.06", self.workspace)
        destination.mkdir(parents=True)
        previous = destination / "summary.tsv"
        previous.write_text("preserve this export\n", encoding="utf-8")

        def produce_incomplete_schema(command, _headless, _workspace):
            stage = Path(command[-1])
            self.write_minimal_exports(
                stage,
                "40.06",
                expected,
                instruction_header="address\tbytes\tmnemonic\toperands",
                function_header="entry\tname\tbody_start\tbody_end\tname_status",
            )

        with (
            mock.patch.object(
                pipeline, "run_headless", side_effect=produce_incomplete_schema
            ),
            self.assertRaisesRegex(pipeline.PipelineError, "containing_function_entry"),
        ):
            self.run_fake_export(self.workspace, expected)

        self.assertEqual(previous.read_text(encoding="utf-8"), "preserve this export\n")

    def test_headless_script_error_is_rejected_even_with_zero_exit(self):
        result = mock.Mock(returncode=0, stdout="ERROR REPORT SCRIPT ERROR: failure\n")
        with (
            mock.patch.object(pipeline, "ghidra_environment", return_value={}),
            mock.patch.object(pipeline.subprocess, "run", return_value=result),
            self.assertRaisesRegex(pipeline.PipelineError, "script error"),
        ):
            pipeline.run_headless(["project"], "analyzeHeadless", self.workspace)

    def test_bad_version_tracking_report_preserves_previous_report(self):
        destination = self.workspace / "comparison" / "vt-exact-functions.tsv"
        destination.parent.mkdir(parents=True)
        previous = (
            "# Candidate matches only; no names or markup were applied.\nprevious\n"
        )
        destination.write_text(previous, encoding="utf-8")

        def produce_bad_report(command, _headless, _workspace):
            Path(command[-1]).write_text("incomplete\n", encoding="utf-8")

        with (
            mock.patch.object(
                pipeline,
                "read_verified_input",
                return_value=(b"image", Path("image"), Path("listing")),
            ),
            mock.patch.object(
                pipeline, "read_verified_findings", return_value=(Path("tsv"), b"tsv")
            ),
            mock.patch.object(pipeline, "require_project_present"),
            mock.patch.object(pipeline, "validate_ghidra_exports"),
            mock.patch.object(pipeline, "validate_exports"),
            mock.patch.object(pipeline, "validate_findings_export"),
            mock.patch.object(
                pipeline, "run_headless", side_effect=produce_bad_report
            ) as run,
            self.assertRaisesRegex(pipeline.PipelineError, "provenance"),
        ):
            pipeline.compare_functions(self.workspace, "analyzeHeadless")

        self.assertIn("-readOnly", run.call_args.args[0])
        self.assertEqual(destination.read_text(encoding="utf-8"), previous)


if __name__ == "__main__":
    unittest.main()
