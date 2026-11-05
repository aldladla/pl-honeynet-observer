"""Conservative command-intent rules. Parses strings only; never executes input."""
import re,shlex
from functools import lru_cache
from pathlib import PurePosixPath

CATEGORIES=('recon','writable','delivery','execution','persistence_cleanup')
LABELS={'recon':'Rozpoznawanie systemu i sprzętu','writable':'Próby zapisu w katalogach','delivery':'Dostarczanie plików','execution':'Uprawnienia i próby uruchomienia','persistence_cleanup':'Trwały dostęp i usuwanie śladów'}
def _segments(command):
 try:
  lex=shlex.shlex(command,posix=True,punctuation_chars=';&|<>()');lex.whitespace_split=True;lex.commenters='#';tokens=list(lex)
 except ValueError:return []
 result=[];current=[]
 for token in tokens:
  if token in (';','&&','||','|','&','(',')'):
   if current:result.append(current);current=[]
  else:current.append(token)
 if current:result.append(current)
 return result
@lru_cache(maxsize=30000)
def _classify(command,depth=0):
 found=set()
 if depth>3 or len(command)>131072:return frozenset()
 for original in _segments(command):
  t=list(original)
  while t and (t[0] in ('if','then','elif','else','do','!') or re.match(r'^[A-Za-z_][A-Za-z_0-9]*=',t[0])):t.pop(0)
  if not t:continue
  targets=[t[i+1] for i,x in enumerate(t[:-1]) if x in ('>','>>','>|')]
  if any('/' in x and re.search(r'/(?:\.x|\.test|\.write_test|\.probe)$',x) for x in targets):found.add('writable')
  while t and (t[0].isdigit() or t[0] in ('>','>>','<','<<')):
   if t[0] in ('>','>>','<','<<'):t=t[2:]
   else:t=t[1:]
  if not t:continue
  name=PurePosixPath(t[0]).name
  if name in ('sudo','env','command','nohup'):
   t=t[1:]
   while t and (t[0].startswith('-') or re.match(r'^[A-Za-z_][A-Za-z_0-9]*=',t[0])):
    option=t.pop(0)
    if option in ('-u','-g') and t:t.pop(0)
   if not t:continue
   name=PurePosixPath(t[0]).name
  if name=='busybox' and len(t)>1:t=t[1:];name=PurePosixPath(t[0]).name
  args=t[1:];joined=' '.join(args)
  if name in ('sh','bash','dash','ash'):
   if '-c' in args and args.index('-c')+1<len(args):found.update(_classify(args[args.index('-c')+1],depth+1))
   elif '-s' in args:found.add('delivery')
   elif args and not args[0].startswith('-'):found.add('execution')
  if name in ('uname','lscpu','nproc','lspci','nvidia-smi','free','uptime','whoami','id','ps','top','lsblk','hostname','getconf','sw_vers') or (name=='sysctl' and '-n' in args):found.add('recon')
  if name in ('cat','head','hexdump','dd') and re.search(r'(?:/proc/(?:cpuinfo|meminfo|uptime|version)|/etc/(?:os-release|issue|debian_version|redhat-release)|/bin/(?:ls|busybox))',joined):found.add('recon')
  if name=='curl' and re.search(r'(?:ipinfo\.io/ip|api\.ipify\.org|ifconfig\.me)',joined):found.add('recon')
  if name in ('touch','mktemp','mkdir') or (name in ('test','[') and '-w' in args):found.add('writable')
  real_targets=[x for x in targets if x not in ('/dev/null','/dev/stdout','/dev/stderr','&1','&2')]
  if name in ('echo','printf','cat','base64','xxd') and real_targets:found.add('delivery')
  if name in ('wget','curl') and any(re.match(r'^(?:https?|ftp)://',a) for a in args):
   if not (name=='curl' and 'recon' in found):found.add('delivery')
  if name in ('scp','sftp','tftp','ftpget') and args:found.add('delivery')
  if name=='chmod' or re.match(r'^(?:\./|/(?:tmp|var/tmp|dev/shm|home|root)/)',t[0]):found.add('execution')
  if (name=='crontab' and args!=['-l']) or (name=='history' and any(a in ('-c','-w') for a in args)):found.add('persistence_cleanup')
  if name=='systemctl' and any(a in ('enable','link') for a in args):found.add('persistence_cleanup')
  if any(re.search(r'(?:\.ssh/authorized_keys|/etc/cron|\.bashrc|\.profile|/systemd/system/)',x) for x in real_targets):found.add('persistence_cleanup')
  if name in ('rm','truncate','shred') and re.search(r'(?:\.bash_history|\.zsh_history|/var/log/|\$HISTFILE|\$0)',joined):found.add('persistence_cleanup')
  if name in ('unset','export') and ('HISTFILE' in joined or 'HISTSIZE=0' in joined):found.add('persistence_cleanup')
 return frozenset(found)
def classify(command):return set(_classify(command))
def session_actions(commands):
 result=set()
 for command in commands:result.update(_classify(command))
 return result
