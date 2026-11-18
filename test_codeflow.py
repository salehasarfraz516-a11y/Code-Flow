from pathlib import Path
import tempfile
import unittest

import codeflow


class CodeFlowTests(unittest.TestCase):
    def analyze(self, source: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lab.py"
            path.write_text(source, encoding="utf-8")
            tree, _ = codeflow.parse_file(path)
            return codeflow.TaintAnalyzer(tree, str(path)).analyze()

    def test_parse_and_print_function_names(self):
        tree = codeflow.ast.parse("def alpha():\n    pass\n\ndef beta():\n    pass\n")
        names = [
            node.name
            for node in codeflow.ast.walk(tree)
            if isinstance(node, codeflow.ast.FunctionDef)
        ]
        self.assertEqual(names, ["alpha", "beta"])

    def test_sources_only_selected_calls_are_tainted(self):
        flows = self.analyze(
            "a = input()\n"
            "b = str(a)\n"
            "eval(a)\n"
            "print(b)\n"
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].source_line, 1)
        self.assertEqual(flows[0].sink_line, 3)

    def test_assignment_chain_is_tainted(self):
        flows = self.analyze("x = input()\ny = x\nexec(y)\n")
        self.assertEqual(len(flows), 1)
        self.assertIn("exec", flows[0].sink)

    def test_clean_sink_is_not_reported(self):
        flows = self.analyze("safe = 'hello'\nos.system('echo hello')\n")
        self.assertEqual(flows, [])

    def test_cross_function_argument_is_traced(self):
        flows = self.analyze(
            "def run(command):\n"
            "    os.system(command)\n"
            "\n"
            "data = input()\n"
            "run(data)\n"
        )
        sink_flows = [flow for flow in flows if flow.sink_kind == "command_execution"]
        self.assertEqual(len(sink_flows), 1)
        self.assertEqual(sink_flows[0].sink_line, 2)

    def test_database_sink(self):
        flows = self.analyze("name = input()\ncursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n")
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_kind, "sql_query")


if __name__ == "__main__":
    unittest.main()
