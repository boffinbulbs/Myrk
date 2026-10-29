from pathlib import Path
import subprocess
import tempfile
import unittest

import check_scope


class ScopeTests(unittest.TestCase):
    def test_only_canonical_laboratory_paths_can_omit_shared_checks(self):
        self.assertFalse(check_scope.shared_checks(['research/storage-pcs/backend/src/storage.rs','research/storage-pcs/README.md']))
        for paths in [[],['README.md'],['Cargo.lock'],['crates/thorum-core/src/lib.rs'],
                      ['research/storage-matrix/src/lib.rs'],['.github/workflows/checks.yml'],
                      ['.github/scripts/check_scope.py'],['research/storage-pcs/../other.rs'],
                      ['research/storage-pcs//bad'],['research/storage-pcs\\bad'],
                      ['research/storage-pcs/a\n.rs'],['research/storage-pcs/'],
                      ['research/storage-pcs/a.rs','unknown.rs']]:
            with self.subTest(paths=paths): self.assertTrue(check_scope.shared_checks(paths))

    def test_manual_missing_and_invalid_events_select_shared_checks(self):
        for event_name,event in [('workflow_dispatch',{}),('push',{}),('pull_request',{}),
                                 ('push',{'before':'0'*40,'after':'a'*40}),
                                 ('push',{'before':'HEAD;invalid','after':'a'*40}),
                                 ('pull_request',{'pull_request':None})]:
            with self.subTest(event=event):
                self.assertTrue(check_scope.select(event_name,event,Path.cwd())['core'])

    def test_nonexistent_revisions_select_shared_checks(self):
        self.assertTrue(check_scope.select('push',dict(before='a'*40,after='b'*40),Path.cwd())['core'])

    def test_git_ranges_include_deleted_side_of_a_rename(self):
        temporary_root=Path.cwd().resolve()
        with tempfile.TemporaryDirectory(prefix='.kova_scope_',dir=temporary_root) as directory:
            root=Path(directory).resolve()
            self.assertTrue(root.is_relative_to(temporary_root))
            def git(*args):
                result=subprocess.run(['git',*args],cwd=root,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                return result.stdout.strip()
            git('init','-q')
            git('config','user.name','Scope test fixture')
            git('config','user.email','fixture@example.invalid')
            (root/'Cargo.toml').write_text('[workspace]\nmembers=[]\n',encoding='utf8')
            (root/'shared.rs').write_text('synthetic shared source\n',encoding='utf8')
            git('add','shared.rs','Cargo.toml')
            git('commit','-qm','Synthetic source fixture')
            before=git('rev-parse','HEAD')
            folder=root/'research/storage-pcs'
            folder.mkdir(parents=True)
            git('mv','shared.rs','research/storage-pcs/moved.rs')
            git('commit','-qm','Synthetic rename fixture')
            after=git('rev-parse','HEAD')
            event=dict(before=before,after=after)
            paths=check_scope.changed_paths('push',event,root)
            self.assertIn('shared.rs',paths)
            self.assertIn('research/storage-pcs/moved.rs',paths)
            self.assertTrue(check_scope.select('push',event,root)['core'])
            before=after
            (folder/'moved.rs').write_text('changed synthetic source\n',encoding='utf8')
            git('commit','-qam','Synthetic isolated fixture')
            after=git('rev-parse','HEAD')
            self.assertFalse(check_scope.select('push',dict(before=before,after=after),root)['core'])
            request=dict(pull_request=dict(base=dict(sha=before),head=dict(sha=after)))
            self.assertFalse(check_scope.select('pull_request',request,root)['core'])
            for manifest in ['[workspace]\nmembers=["research/*"]\n',
                             '[package]\nname="fixture"\nversion="0.0.0"\n[dependencies]\nproof={path="research/storage-pcs"}\n',
                             '[malformed\n']:
                (root/'Cargo.toml').write_text(manifest,encoding='utf8')
                git('commit','-qam','Synthetic dependency boundary fixture')
                before=git('rev-parse','HEAD')
                with (folder/'moved.rs').open('a',encoding='utf8') as output:
                    output.write('another synthetic change\n')
                git('commit','-qam','Synthetic dependent fixture')
                after=git('rev-parse','HEAD')
                self.assertTrue(check_scope.select('push',dict(before=before,after=after),root)['core'])


if __name__=='__main__': unittest.main()
