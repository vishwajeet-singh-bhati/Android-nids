"""Render the SMS/URL report part from pinned aggregate evidence."""
import json
import re
from pathlib import Path


def render(table, esc, pct):
    root = Path(__file__).resolve().parents[2]
    d = json.loads((root / 'docs/project_report/ADDON_MODELS_EVIDENCE.json').read_text(encoding='utf-8'))
    sms = d['neural_source']
    rows = []
    for split, record in sms['split']['splits'].items():
        labels = record['labels']
        rows.append([esc(split), str(record['rows'])] + [str(labels[x]) for x in ['ham', 'spam', 'smishing']])
    tokens = {'SMS_DATA': table(['Split', 'Rows', 'Ham', 'Spam', 'Smishing'], rows)}
    models = sms['comparison']['models']
    choices = [('FP32', 'fp32'), ('PTQ export b1', 'ptq_pte_b1'), ('QAT export b1', 'qat_pte_b1')]
    rows = [[name] + [pct(models[key][x], 2) for x in ['accuracy', 'macro_f1', 'smishing_precision', 'smishing_recall']]
            for name, key in choices]
    tokens['SMS_COMPARISON'] = table(['Model', 'Accuracy', 'Macro F1', 'Smishing P', 'Smishing R'], rows)
    ptq = models['ptq_pte_b1']['per_class']
    tokens['SMS_CLASSWISE'] = table(['Class', 'Support', 'Precision', 'Recall', 'F1'],
        [[name, str(ptq[name]['support'])] + [pct(ptq[name][key], 2) for key in ['precision', 'recall', 'f1']]
         for name in ['ham', 'spam', 'smishing']])
    url = d['url']
    assert url['rows'] == 2048 and url['label_summary']['exact_feed_confirmed_phishing'] == 218
    assert url['known_positive_raw_outcomes'] == {'UNCERTAIN': 30, 'PHISHING': 172, 'LIKELY_SAFE': 16}
    tokens['URL_SUMMARY'] = table(['Final outcome', 'URLs'],
        [[esc(k), str(v)] for k, v in url['deployed']['decisions'].items()] + [['Failures', '0']])
    tokens['URL_KNOWN'] = table(['View on known positives', 'Phishing', 'Uncertain', 'Likely safe'],
        [['Pipeline with lists/rules', '218', '0', '0'], ['Raw learned ensemble', '172', '30', '16']], 'lrrr')
    text = (Path(__file__).parent / 'addon_models_chapters.tex').read_text(encoding='utf-8')
    for key, value in tokens.items():
        text = text.replace('@@' + key + '@@', value)
    protected = []
    def hold(match):
        protected.append(match.group(0))
        return '@@HOLD' + chr(65 + len(protected) - 1) + '@@'
    text = re.sub(r'\\begin\{lstlisting\}.*?\\end\{lstlisting\}|\\code\{[^}]*\}|\b(?:FP32|INT8|INT4|F1)\b',
                  hold, text, flags=re.S)
    text = re.sub(r'(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])', ' ', text)
    for i, value in enumerate(protected):
        text = text.replace('@@HOLD' + chr(65 + i) + '@@', value)
    assert '@@' not in text
    return text
