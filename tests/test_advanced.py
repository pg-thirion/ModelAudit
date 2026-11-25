import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from modelaudit.advanced import check_rules, select_cases, plan, export_report, validate_rules
from modelaudit.adapters import HttpTarget, Response, DemoTarget
from modelaudit.cli import main
from modelaudit.engine import evaluate, exit_code
from modelaudit.suite import Case, load_suite


def case(**kw):
    return Case('case', 'policy', 'high', 'first', (), ('secret',), **kw)


class RulesTests(unittest.TestCase):
    def test_rules(self):
        for text, rules, latency, expected in [
            ('OK', {'exact': 'OK'}, 1, []), ('ok', {'exact': 'OK'}, 1, ['exact']),
            ('allowed', {'any_of': ['yes', 'allowed']}, 1, []), ('no', {'any_of': ['yes']}, 1, ['any_of']),
            ('a', {'min_chars': 2}, 1, ['min_chars']), ('abc', {'max_chars': 2}, 1, ['max_chars']),
            ('{}', {'json_object': True}, 1, []), ('[]', {'json_object': True}, 1, ['json_object']),
            ('{"x":1,"x":2}', {'json_object': True}, 1, ['json_object']),
            ('{"x":NaN}', {'json_object': True}, 1, ['json_object']),
            ('{}', {'required_keys': ['x']}, 1, ['required_keys']),
            ('{"x":1}', {'forbidden_keys': ['x']}, 1, ['forbidden_keys']),
            ('okay', {'max_latency_ms': 5}, 6, ['max_latency_ms']),
            ('ＹＥＳ', {'any_of': ['yes'], 'normalize': True}, 1, []),
        ]:
            with self.subTest(text=text, rules=rules):
                self.assertEqual(check_rules(text, validate_rules(rules), latency), expected)

    def test_invalid_rules(self):
        for rules in [None, {'unknown': 1}, {'exact': ''}, {'min_chars': True},
                      {'normalize': 1}, {'any_of': []}, {'min_chars': 3, 'max_chars': 2},
                      {'required_keys': ['x'], 'forbidden_keys': ['x']}]:
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                validate_rules(rules)

    def test_suite_extended_fields(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'suite.json'
            row = {'id': 'test', 'category': 'policy', 'severity': 'low', 'prompt': 'a',
                   'followups': ['b'], 'rules': {'exact': 'ok'}}
            p.write_text(json.dumps([row]))
            self.assertEqual(load_suite(p)[0].followups, ('b',))
            row['followups'] = [1]
            p.write_text(json.dumps([row]))
            with self.assertRaises(ValueError):
                load_suite(p)


class ExecutionTests(unittest.TestCase):
    def test_multiturn_history_and_isolation(self):
        target = HttpTarget('https://example.invalid', 'chat', 'demo', 1)
        target.token = None
        histories = []
        def respond(messages):
            histories.append([dict(m) for m in messages])
            return Response('secret' if len(messages) == 1 else 'safe', ('audit_read',))
        with patch.object(target, '_request', side_effect=respond):
            report = evaluate([case(followups=('second',))], target, 2)
        self.assertEqual(exit_code(report), 1)
        self.assertEqual([len(h) for h in histories], [1, 3, 1, 3])
        self.assertEqual(histories[1][1], {'role': 'assistant', 'content': 'secret'})
        self.assertNotIn('secret', json.dumps(report))

    def test_normalized_forbidden_and_rules(self):
        class Target:
            def respond(self, c):
                return Response('ＳＥＣＲＥＴ')
        report = evaluate([case(rules={'normalize': True, 'exact': 'safe'})], Target())
        trial = report['results'][0]['trials'][0]
        self.assertEqual(trial['matched_forbidden_indexes'], [0])
        self.assertEqual(trial['rule_failures'], ['exact'])

    def test_missing_evidence_on_any_turn(self):
        target = HttpTarget('https://example.invalid', 'generic', None, 1)
        with patch.object(target, '_request', side_effect=[Response('ok'), Response('ok', ())]):
            report = evaluate([case(followups=('second',), forbidden_events=('write',))], target)
        self.assertEqual(exit_code(report), 2)

    def test_selection_and_plan(self):
        cases = [case(followups=('second',)), Case('other', 'control', 'low', 'a', ('ok',), ())]
        self.assertEqual(select_cases(cases, ['policy'], ['high'], ['case']), cases[:1])
        self.assertEqual(select_cases(cases, seed=7), select_cases(cases, seed=7))
        self.assertEqual(plan(cases, 2, 6)['max_requests'], 6)
        with self.assertRaises(ValueError):
            plan(cases, 2, 5)
        with self.assertRaises(ValueError):
            select_cases(cases, ids=['missing'])
        with self.assertRaises(ValueError):
            select_cases(cases, ['policy'], ['low'])

    def test_pacing_deadline_and_metrics(self):
        class Alternating:
            n = 0
            def respond(self, c):
                self.n += 1
                return Response('safe' if self.n == 1 else 'secret')
        with patch('modelaudit.engine.sleep') as pause:
            report = evaluate([case()], Alternating(), 2, interval=.1)
        pause.assert_called_once_with(.1)
        self.assertEqual(report['metrics']['flaky_cases'], ['case'])
        self.assertEqual(report['metrics']['trial_pass_rate'], 50)
        self.assertEqual(report['metrics']['weighted_pass_rate'], 0)
        self.assertIsNotNone(report['metrics']['latency_ms']['p95'])
        target = Alternating()
        with patch('modelaudit.engine.perf_counter', side_effect=[0, 2, 2.1]):
            report = evaluate([case()], target, deadline=1)
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(target.n, 0)
        self.assertIsNone(report['metrics']['latency_ms']['median'])
        with self.assertRaises(ValueError):
            evaluate([case()], target, interval=-1)

    def test_report_formats_and_plan_cli(self):
        with tempfile.TemporaryDirectory() as d:
            paths = [Path(d) / f'report.{ext}' for ext in ('csv', 'xml', 'html')]
            with patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--plan', '--category', 'positive_control']), 0)
                self.assertEqual(main(['--demo', 'vulnerable', '--csv', str(paths[0]),
                                       '--junit', str(paths[1]), '--html', str(paths[2])]), 1)
            self.assertEqual(len(list(csv.DictReader(io.StringIO(paths[0].read_text())))), 8)
            self.assertEqual(ET.parse(paths[1]).getroot().attrib['failures'], '6')
            self.assertIn('Gate: fail', paths[2].read_text())
            self.assertNotIn('AUDIT_FAKE_SECRET', paths[2].read_text())
            with self.assertRaises(ValueError):
                export_report({'results': []}, 'bad')
