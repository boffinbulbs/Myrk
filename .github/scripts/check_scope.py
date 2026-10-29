"""Select shared checks conservatively for an isolated laboratory change."""
import json
import os
from pathlib import Path
import re
import subprocess
import fnmatch
import tomllib


def shared_checks(paths):
    if not paths:
        return True
    for path in paths:
        parts=path.split('/')
        if (not path.startswith('research/storage-pcs/') or '\\' in path
                or any(part in ('','.','..') for part in parts)
                or any(ord(char)<32 for char in path)):
            return True
    return False


def isolated_dependency_boundary(repository):
    repository=Path(repository).resolve()
    laboratory=(repository/'research/storage-pcs').resolve()
    result=subprocess.run(['git','ls-files','-z','--','*Cargo.toml'],cwd=repository,
                          capture_output=True,check=True,timeout=15)
    manifests=[name for name in result.stdout.decode('utf8').split('\0') if name]
    if not manifests:
        return False
    def incoming(value,parent):
        if isinstance(value,dict):
            for key,item in value.items():
                if key=='path':
                    if not isinstance(item,str) or (parent/item).resolve().is_relative_to(laboratory):
                        return True
                if incoming(item,parent):
                    return True
        elif isinstance(value,list):
            return any(incoming(item,parent) for item in value)
        return False
    for name in manifests:
        path=repository/name
        if path.is_symlink():
            return False
        if path.resolve().is_relative_to(laboratory):
            continue
        data=tomllib.loads(path.read_text(encoding='utf8'))
        if incoming(data,path.parent):
            return False
        relative=os.path.relpath(laboratory,path.parent).replace('\\','/')
        for pattern in data.get('workspace',{}).get('members',[]):
            if not isinstance(pattern,str) or fnmatch.fnmatchcase(relative,pattern.rstrip('/')):
                return False
    return True


def changed_paths(event_name,event,repository):
    if event_name=='push':
        before,after=event.get('before'),event.get('after')
    elif event_name=='pull_request':
        request=event.get('pull_request',{})
        before=request.get('base',{}).get('sha')
        after=request.get('head',{}).get('sha')
    else:
        return None
    for revision in (before,after):
        if (not isinstance(revision,str) or not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}',revision)
                or set(revision)=={'0'}):
            return None
        result=subprocess.run(['git','cat-file','-e',revision+'^{commit}'],cwd=repository,capture_output=True,timeout=15)
        if result.returncode:
            return None
    result=subprocess.run(['git','diff','--no-renames','--name-only','-z',before,after],
                          cwd=repository,capture_output=True,check=True,timeout=15)
    paths=result.stdout.decode('utf8').split('\0')
    return [path for path in paths if path]


def select(event_name,event,repository):
    try:
        paths=changed_paths(event_name,event,repository)
        if paths is None:
            return dict(core=True,reason='unavailable_or_full_range',path_count=0)
        core=shared_checks(paths) or not isolated_dependency_boundary(repository)
        return dict(core=core,reason='shared_or_unknown_change' if core else 'isolated_proof_change',path_count=len(paths))
    except (OSError,ValueError,subprocess.SubprocessError,AttributeError,TypeError):
        return dict(core=True,reason='range_check_failed',path_count=0)


def main():
    try:
        event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf8'))
        result=select(os.environ.get('GITHUB_EVENT_NAME',''),event,Path.cwd())
    except (OSError,ValueError,KeyError):
        result=dict(core=True,reason='event_unavailable',path_count=0)
    with Path(os.environ['GITHUB_OUTPUT']).open('a',encoding='utf8',newline='\n') as output:
        output.write('core='+str(result['core']).lower()+'\n')
    print(json.dumps(result))


if __name__=='__main__':
    main()
