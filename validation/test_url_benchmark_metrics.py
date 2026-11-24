import unittest

from validation.benchmark_phone_urls import binary_metrics, summarize


class BenchmarkMetricsTests(unittest.TestCase):
    def test_balanced_confusion_counts(self):
        m = binary_metrics([1, 1, 0, 0], [1, 0, 1, 0])
        self.assertEqual([m[k] for k in ['tp', 'fn', 'fp', 'tn']], [1, 1, 1, 1])
        for key in ['accuracy', 'precision', 'recall', 'f1', 'specificity', 'balanced_accuracy']:
            self.assertEqual(m[key], .5)
        self.assertEqual(m['mcc'], 0)

    def test_positive_only_does_not_claim_full_accuracy(self):
        m = binary_metrics([1, 1, 1], [1, 1, 0])
        self.assertEqual(m['recall'], 2 / 3)
        for key in ['accuracy', 'precision', 'f1', 'specificity', 'negative_predictive_value']:
            self.assertIsNone(m[key])

    def test_uncertain_counts_as_missed_in_primary_view(self):
        rows = [dict(id=i, elapsed_ms=1, result=dict(decision=d))
                for i, d in enumerate(['PHISHING', 'UNCERTAIN', 'LIKELY_SAFE'], 1)]
        s = summarize(rows, {1: 1, 2: 1, 3: 0})['metrics']
        self.assertEqual(s['phishing_detection']['recall'], .5)
        self.assertEqual(s['decisive_only']['recall'], 1)
        self.assertEqual(s['decisive_coverage'], 2 / 3)

    def test_unlabeled_rows_never_become_negative_truth(self):
        rows = [dict(id=1, elapsed_ms=1, result=dict(decision='PHISHING'))]
        self.assertIsNone(summarize(rows)['metrics'])


if __name__ == '__main__':
    unittest.main()
