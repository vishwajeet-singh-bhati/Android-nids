"""Embed audited numerical tables into a single Overleaf-ready LaTeX document."""
from datetime import datetime
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
FOLDER=ROOT/'docs/project_report'
DATA=json.loads((FOLDER/'REPORT_EVIDENCE.json').read_text(encoding='utf-8'))
CLASSES=DATA['classes']


def esc(value):
    mapping={'\\':r'\textbackslash{}','&':r'\&','%':r'\%','$':r'\$','#':r'\#','_':r'\_','{':r'\{','}':r'\}','~':r'\textasciitilde{}','^':r'\textasciicircum{}'}
    return ''.join(mapping.get(c,c) for c in str(value))


def pct(value,digits=3):return f'{100*value:.{digits}f}'
def integer(value):return f'{int(value):,}'


def table(headers,rows,spec=None,small=True):
    spec=spec or ('l'+'r'*(len(headers)-1))
    start=('\n{\\small\n' if small else '\n{\n')+r'\begin{longtable}{@{}'+spec+r'@{}}'+'\n'+r'\toprule'+'\n'
    start+=' & '.join(headers)+r'\\\midrule\endhead'+'\n'
    body='\n'.join(' & '.join(map(str,row))+r'\\' for row in rows)
    return start+body+'\n'+r'\bottomrule\end{longtable}'+'\n}\n'


def triple(row):return ' / '.join(pct(row[k],2) for k in ['precision','recall','f1-score'])


def class_table(records):
    return table(['Class']+[esc(name)+r' $P/R/F_1$' for name,_ in records],
                 [[esc(c)]+[triple(r[c]) for _,r in records] for c in CLASSES],
                 'l'+'r'*len(records))


def build():
    p=DATA['paper'];context=DATA['context'];a=DATA['aligned'];pipe=a['pipeline'];repair=DATA['repair'];b=repair['baseline'];r=repair['selected'];new=DATA['phone_augmentation']
    tokens={}
    tokens['AS_OF']=esc(datetime.fromisoformat(DATA['as_of_ist']).strftime('%d %B %Y, %H:%M IST'))
    tokens['TRAINING_DONE']=str(DATA['training_status']['completed'])
    tokens['PAPER_COUNTS']=table(['Class','Train','Test','Retained total'],[[esc(c),integer(p['data']['train_class_counts'][c]),integer(p['data']['test_class_counts'][c]),integer(p['data']['train_class_counts'][c]+p['data']['test_class_counts'][c])] for c in CLASSES])
    tokens['ALIGNED_COUNTS']=table(['Class','Train views','Validation views','Test views'],[[esc(c)]+[integer(a['counts'][s][i]) for s in ['train','validation','test']] for i,c in enumerate(CLASSES)])
    tokens['SOURCE_COUNTS']=table(['Aligned source','Train views','Validation views','Test views'],[[esc(c)]+[integer(a['source_counts'][s][c]) for s in ['train','validation','test']] for c in ['Monday','Tuesday','Wednesday','Thursday','Friday','PARROT','AAGM']])
    fine=['FTP-Patator','SSH-Patator','DoS GoldenEye','DoS Hulk','DoS Slowhttptest','DoS slowloris','Web Attack Brute Force','Web Attack XSS','Web Attack Sql Injection']
    tokens['FINE_COUNTS']=table(['Selected fine label','Train','Validation','Test'],[[esc(c)]+[integer(a['fine_counts'][s].get(c,0)) for s in ['train','validation','test']] for c in fine])
    names={'baseline':'Baseline','pruned_30':r'Pruned 30\%','pruned_40':r'Pruned 40\%'}
    rows=[]
    for name,model in p['models'].items():
        m=model['test'];rows.append([names[name],pct(m['accuracy'],4),pct(m['macro_f1'],4),pct(m['binary_attack_recall'],4),pct(m['benign_false_positive_rate'],5),integer(m['binary_confusion'][0][1])])
    tokens['PAPER_SUMMARY']=table(['Variant','Accuracy','Macro F1','Attack recall','Benign FPR','Benign FP'],rows)
    rows=[]
    for name,model in p['models'].items():
        m=model['test'];rows.append([names[name], ' / '.join(pct(m[k],3) for k in ['macro_precision','macro_recall','macro_f1']),
            ' / '.join(pct(m[k],3) for k in ['weighted_precision','weighted_recall','weighted_f1'])])
    tokens['PAPER_AVERAGES']=table(['Variant',r'Macro $P/R/F_1$',r'Weighted $P/R/F_1$'],rows)
    tokens['PAPER_CLASSWISE']=class_table([(name,p['models'][key]['test']['classification_report']) for name,key in [('Baseline','baseline'),('Pruned 30%','pruned_30'),('Pruned 40%','pruned_40')]])
    rows=[]
    for name,key in [('Control, unpruned','control_baseline'),('Context, unpruned','context_baseline'),('Control, pruned 30%','control_pruned_30'),('Context, pruned 30%','context_pruned_30')]:
        m=context[key];rows.append([esc(name),pct(m['accuracy'],4),pct(m['macro_f1'],4),pct(m['binary_attack_recall'],4),pct(m['benign_false_positive_rate'],5)])
    tokens['CONTEXT_SUMMARY']=table(['Same-size arm','Accuracy','Macro F1','Attack recall','Benign FPR'],rows)
    tokens['CONTEXT_CLASSWISE']=class_table([('Original pruned',p['models']['pruned_30']['test']['classification_report']),('Same-size control',context['control_pruned_30']['classification_report']),('With context',context['context_pruned_30']['classification_report'])])
    metrics=pipe['binary'];n=sum(a['counts']['test']);accuracy=sum(pipe['confusion_with_unknown'][i][i] for i in range(7))/n
    tokens['ALIGNED_SUMMARY']=table(['Selected full-pipeline metric','Value'],[
        ['Typed accuracy',pct(accuracy,4)+r'\%'],['Typed macro F1',pct(pipe['classwise']['macro avg']['f1-score'],4)+r'\%'],
        ['Binary precision / recall',pct(metrics['precision'],4)+' / '+pct(metrics['recall'],4)+r'\%'],
        ['Benign false flags / total',integer(metrics['fp'])+' / '+integer(a['counts']['test'][0])],
        ['Missed attack-labeled views',integer(metrics['fn'])],['Gate threshold / type threshold','0.7858333333 / 0.6']], r'p{0.57\textwidth}r')
    rows=[]
    for c in CLASSES:
        m=pipe['classwise'][c];recall='--' if c=='Benign' else pct(metrics['class_attack_recall'][c],3)
        rows.append([esc(c),integer(m['support']),pct(m['precision']),pct(m['recall']),pct(m['f1-score']),recall])
    tokens['ALIGNED_CLASSWISE']=table(['Class','Support','Typed P','Typed R','Typed F1','Gate recall'],rows)
    rows=[]
    for row in DATA['dry_runs']:
        if row['cohort']!='opened aligned v2 test':continue
        v=row['v2'];star='' if v['diagnosis_would_run'] else '*'
        rows.append([esc(row['known_label']),str(row['index']),f"{v['gate_probability']:.6f}",'Yes' if v['diagnosis_would_run'] else 'No',esc(v['diagnosis_argmax'])+star,esc(v['final_type'])])
    tokens['ALIGNED_DRY']=table(['Reference label','Old row','Gate score','Route?','Diagnosis max','Final v2'],rows)+r'An asterisk marks a counterfactual diagnosis computed for analysis even though the live gate would skip it.'
    tokens['REPAIR_SUMMARY']=table(['Matched metric','V2','Repair'],[
        ['Binary precision',pct(b['binary']['precision'],5),pct(r['binary']['precision'],5)],
        ['Binary recall',pct(b['binary']['recall'],5),pct(r['binary']['recall'],5)],
        ['Binary F1',pct(b['binary']['f1'],5),pct(r['binary']['f1'],5)],
        ['Benign FPR',pct(b['binary']['benign_fpr'],5),pct(r['binary']['benign_fpr'],5)],
        ['Typed macro F1',pct(b['macro_f1'],4),pct(r['macro_f1'],4)],
        ['Benign flags',integer(b['binary']['fp']),integer(r['binary']['fp'])],
        ['Attack misses',integer(b['binary']['fn']),integer(r['binary']['fn'])]])
    tokens['REPAIR_CLASSWISE']=class_table([('Preserved v2',b['classwise']),('Selected repair',r['classwise'])])
    actions=['http_password_guessing','http_password_spraying','sql_injection','xss','normal_http','successful_login','ordinary_failed_login','normal_search_or_code','normal_page','ordinary_server_error','legitimate_http_burst']
    rows=[]
    for action in actions:
        v=[new['splits'][s]['phone_subtypes'].get(action,0) for s in ['train','validation','test']]
        rows.append([esc(action.replace('_',' '))]+[integer(x) for x in v]+[integer(sum(v))])
    rows.append([r'\textbf{Unique total}']+[integer(new['unique_new_phone_rows'][s]) for s in ['train','validation','test']]+['1,216'])
    tokens['PHONE_COUNTS']=table(['Unique controlled subtype','Train','Val.','Test','Total'],rows)
    tokens['AUGMENT_COUNTS']=table(['Partition','Original rows','Unique new','Replay factor','Combined rows'],[[esc(s.title()),integer(v['old_rows']),integer(v['unique_new_phone_rows']),str(v['phone_training_resample_factor']),integer(v['rows'])] for s,v in new['splits'].items()])
    completed=DATA['completed_augmentation'];old=completed['frozen_v2_baseline'];updated=completed['augmented_pipeline']
    rows=[]
    for cohort in ['legacy','phone']:
        for name,source in [('Frozen v2',old),('Augmented v1',updated)]:
            m=source[cohort];z=m['binary'];rows.append([esc(cohort),esc(name),pct(z['precision'],3),pct(z['recall'],3),pct(z['benign_fpr'],4),pct(m['macro_f1_present_classes'],3)])
    tokens['AUGMENT_FINAL_SUMMARY']=table(['Cohort','Version','Binary P','Binary R','Benign FPR','Macro F1'],rows)
    tokens['AUGMENT_LEGACY_CLASSWISE']=class_table([('Frozen v2',old['legacy']['classwise']),('Augmented v1',updated['legacy']['classwise'])])
    tokens['AUGMENT_PHONE_CLASSWISE']=table(['Present class','Support',r'Frozen v2 $P/R/F_1$',r'Augmented $P/R/F_1$'],[[esc(c),integer(updated['phone']['classwise'][c]['support']),triple(old['phone']['classwise'][c]),triple(updated['phone']['classwise'][c])] for c in ['Benign','Web Attack']])
    rows=[]
    for subtype,m in completed['phone_subtypes'].items():
        rows.append([esc(subtype.replace('_',' ')),integer(m['support']),str(round(m['flag_rate']*m['support'])),pct(m['flag_rate'],3),pct(m['correct_family_rate'],3)])
    tokens['AUGMENT_SUBTYPES']=table(['Controlled subtype','Segments','Flagged','Flag rate','Correct family'],rows)
    features=[
        ('Flow Duration','Microseconds'),('Total Fwd Packets','Count'),('Total Backward Packets','Count'),
        ('Total Length of Fwd Packets','Payload bytes'),('Total Length of Bwd Packets','Payload bytes'),
        ('Fwd Packet Length Max','Payload bytes'),('Fwd Packet Length Min','Payload bytes'),('Fwd Packet Length Mean','Payload bytes'),('Fwd Packet Length Std','Payload bytes'),
        ('Bwd Packet Length Max','Payload bytes'),('Bwd Packet Length Min','Payload bytes'),('Bwd Packet Length Mean','Payload bytes'),('Bwd Packet Length Std','Payload bytes'),
        ('Flow Bytes/s','Payload bytes/second'),('Flow Packets/s','Packets/second'),
        ('Flow IAT Mean','Microseconds'),('Flow IAT Std','Microseconds'),('Flow IAT Max','Microseconds'),('Flow IAT Min','Microseconds'),
        ('Fwd IAT Total','Microseconds'),('Fwd IAT Mean','Microseconds'),('Fwd IAT Std','Microseconds'),('Fwd IAT Max','Microseconds'),('Fwd IAT Min','Microseconds'),
        ('Bwd IAT Total','Microseconds'),('Bwd IAT Mean','Microseconds'),('Bwd IAT Std','Microseconds'),('Bwd IAT Max','Microseconds'),('Bwd IAT Min','Microseconds'),
        ('SYN Flag Count','Count'),('RST Flag Count','Count'),('ACK Flag Count','Count')]
    tokens['FEATURES_32']=table(['Position','Feature','Meaning / unit'],[[str(i),esc(n),esc(u)] for i,(n,u) in enumerate(features,1)],r'rp{0.48\textwidth}p{0.30\textwidth}')
    aux=['http requests','http responses','http auth failures','http 4xx','http 5xx','login-like requests','SQL-like requests','script-like requests',
         'TLS prefix seen','cleartext HTTP seen','payload packets','duplicate payload fragments','header buffer full','payload gaps or truncation','basic auth seen','long header seen','SSH banner seen','FTP banner or credentials seen']
    tokens['AUXILIARY']=table(['Combined position','Flow auxiliary observation'],[[str(129+i),esc(name)] for i,name in enumerate(aux)],r'rp{0.72\textwidth}')
    fixture=DATA['software_fixture'];rows=[]
    for name,m in fixture['models'].items():rows.append([esc(name),esc(m['class']),f"{max(m['probabilities']):.6f}",'--'])
    for name,key in [('Aligned v2','v2'),('Selected repair','repair'),('Augmented v1','augmented')]:
        m=fixture[key];rows.append([esc(name),esc(m['final_type']),f"{max(m['diagnosis_probabilities']):.6f}",f"{m['gate_probability']:.6f}"])
    tokens['FIXTURE_RESULTS']=table(['Frozen model/pipeline','Output','Largest diagnosis score','Gate score'],rows,r'p{0.29\textwidth}lrr')
    details=[]
    for row in DATA['dry_runs']:
        details.append(r'\subsection{'+esc(row['cohort']+' -- '+row['known_label']+' example, row '+str(row['index']))+'}')
        details.append('First five raw flow values: '+r'\code{'+', '.join(f'{v:.6g}' for v in row['selected_flow_features'])+'}.')
        rows=[]
        if 'models' in row:
            for name,m in row['models'].items():rows.append([esc(name+' ['+m['class']+']')]+[f'{p:.6f}' for p in m['probabilities']])
        else:
            for name,key in [('v2','v2'),('repair','repair')]:
                m=row[key];rows.append([esc(name+' ['+m['final_type']+']')]+[f'{p:.6f}' for p in m['diagnosis_probabilities']])
            details.append('Diagnosis rows below include counterfactual analysis when routing is false; live routing is stated in the main walkthrough.')
        details.append(table(['Model [final output]','B','Bot','BF','DDoS','DoS','Scan','Web'],rows,r'p{0.26\textwidth}'+'r'*7))
    tokens['DETAILED_DRY']='\n'.join(details)
    rows=[]
    for name,v in a['candidates'].items():
        m=v['binary'];rows.append([esc(name),pct(m['precision'],3),pct(m['recall'],3),pct(m['benign_fpr'],4),'--' if v['typed_macro_f1'] is None else pct(v['typed_macro_f1'],3)])
    tokens['ALIGNED_CANDIDATES']=table(['Component: checkpoint','Attack P','Attack R','Benign FPR','Typed macro F1'],rows,r'p{0.32\textwidth}rrrr')
    rows=[]
    for v in repair['finalists']:
        m=v['binary'];rows.append([esc(v['arm']),str(v['seed']),integer(m['fp']),integer(m['fn']),pct(m['precision'],3),pct(m['recall'],3),pct(v['macro_f1'],3)])
    tokens['REPAIR_CANDIDATES']=table(['Treatment','Seed','FP','FN','Attack P','Attack R','Macro F1'],rows)
    rows=[]
    for cells in DATA['legacy_v5_rows']:
        rows.append([esc(cells[0]),integer(cells[1]),cells[2],f'{float(cells[3])*100:.2f}',cells[4],cells[5],cells[6]])
    tokens['LEGACY_V5']=table(['Old candidate','Params','Epoch','Recall','CIC FP','PARROT','AAGM'],rows,r'p{0.31\textwidth}rrrrrr')
    from current_release_report import render
    tokens['LATER_CHAPTERS']=render(DATA,table,esc,pct)
    from safety_models_report import render as render_safety
    tokens['ADDON_MODELS']=render_safety(table,esc,pct)
    template=(Path(__file__).parent/'report_template.tex').read_text(encoding='utf-8')
    needed=set(re.findall(r'@@([A-Z_0-9]+)@@',template));assert needed==set(tokens),(needed-set(tokens),set(tokens)-needed)
    for key,value in tokens.items():template=template.replace('@@'+key+'@@',value)
    assert '@@' not in template
    target=FOLDER/'Android_NIDS_Project_Report.tex';target.write_text(template,encoding='utf-8',newline='\n')
    (FOLDER/'Rakshak_Project_Report.tex').write_text(template,encoding='utf-8',newline='\n')
    print(json.dumps({'latex':str(target),'bytes':target.stat().st_size,'chapters':len(re.findall(r'\\chapter\{',template)),
                      'external_inputs':False,'zip_created':False},indent=2))


if __name__=='__main__':build()
