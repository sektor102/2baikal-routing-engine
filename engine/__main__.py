import argparse
import json
import sys
from pathlib import Path

from .compiler import build
from .io import load_inputs,load_yaml,write_json
from .model import Invalid
from .network import retrieve
from .policy import baseline_report,classify
from .validation import validate


def main():
    parser=argparse.ArgumentParser(description='2Baikal routing engine')
    parser.add_argument('--root',type=Path,default=Path.cwd())
    sub=parser.add_subparsers(dest='command',required=True)
    fetch=sub.add_parser('fetch')
    fetch.add_argument('--offline',action='store_true')
    sub.add_parser('audit')
    compile=sub.add_parser('build')
    compile.add_argument('--mihomo',type=Path)
    compile.add_argument('--repository')
    compile.add_argument('--previous',type=Path)
    check=sub.add_parser('validate')
    check.add_argument('--mihomo',type=Path)
    check.add_argument('--xray',type=Path)
    check.add_argument('--require-binaries',action='store_true')
    args=parser.parse_args()
    try:
        if args.command=='fetch':
            rows=retrieve(args.root,args.offline)
            print(json.dumps([{'id':r['id'],'retrieval':r['retrieval'],'bytes':r.get('bytes'),
                               'missing_required':r.get('missing_required'),'error':r.get('error')} for r in rows],indent=2))
        elif args.command=='audit':
            _,_,_,personal,friend,inventory=load_inputs(args.root)
            write_json(args.root/'reports/baseline.json',baseline_report(personal,friend,inventory))
            _,review,duplicates=classify(personal,friend,load_yaml(args.root/'rules/policy.yaml'))
            write_json(args.root/'reports/review.json',review)
            print(json.dumps({'personal_rules':len(personal),'friend_rules':sum(map(len,friend.values())),
                              'review':sum(r['status']=='REVIEW' for r in review),'exact_duplicates':len(duplicates)}))
        elif args.command=='build':
            result=build(args.root,args.mihomo.resolve() if args.mihomo else None,args.repository,args.previous)
            print(json.dumps({k:result[k] for k in ['version','changed','publishable','counts']},ensure_ascii=False,indent=2))
        else:
            result=validate(args.root,args.mihomo.resolve() if args.mihomo else None,
                            args.xray.resolve() if args.xray else None,args.require_binaries)
            print(json.dumps({'golden_cases':result['golden_cases'],'schema':result['schema'],
                              'mihomo':bool(args.mihomo),'xray':bool(args.xray)},indent=2))
    except (Invalid,ValueError,OSError) as exc:
        print('FAILED: '+str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    sys.exit(main())
