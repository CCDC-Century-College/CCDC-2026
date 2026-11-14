#!/usr/bin/env python3
"""CCDC Linux Hardening V3.2.1. Run as sysadmin after password rotation.

Zero-hour hardening, evidence capture, and threat-hunting lead generation.
"""
from __future__ import annotations
import datetime as dt, fcntl, getpass, os, re, shlex, shutil, subprocess, sys
from dataclasses import dataclass, field
from pathlib import Path

ADMIN='sysadmin'; PASSWORD=''; PASSWORDS={}; SIGNATURE='Version: 3.2.1 | Author: SAUCE | Date: 11/13/2026'; LOGROOT=Path.home()/'ccdc-logs'; LOCKFILE=Path.home()/'.ccdc-linux-hardening.lock'; LOCK_HANDLE=None
SSHOPTS=['-o','StrictHostKeyChecking=accept-new','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-o','LogLevel=ERROR']
UNUSED=['avahi-daemon.service','avahi-daemon.socket','cups.service','cups.socket','cups.path','cups-browsed.service','bluetooth.service','ModemManager.service']

@dataclass
class Target:
    key:str; label:str; ip:str|None; local:bool=False; active:bool=True; skipped:bool=False
    host:str='unknown'; osid:str='unknown'; errors:list[str]=field(default_factory=list); todos:list[str]=field(default_factory=list); changes:int=0; partials:int=0; service_count:int=0; listener_count:int=0; failed_units:int=0; cron_files:int=0; user_crontabs:int=0; timer_count:int=0; at_jobs:int=0; revoked_users:set[str]=field(default_factory=set); change_records:list[dict]=field(default_factory=list); error_records:list[dict]=field(default_factory=list); finding_records:list[dict]=field(default_factory=list); ssh_status:str='UNKNOWN'; running_count:int=0; enabled_count:int=0; cron_pid_count:int=0; timer_pid_count:int=0; control_status:dict=field(default_factory=dict)
TARGETS=[Target('ubuntu-workstation','Ubuntu Workstation',None,True),Target('kali','Kali Workstation','172.17.0.2'),Target('rocky','Rocky E-Commerce','172.20.240.10'),Target('mail','Ubuntu Email','172.20.240.15'),Target('debian','Debian Splunk OS','172.20.240.20')]

class Logs:
    names=('SUMMARY.txt','ERRORS.txt','TODO.txt','CHANGES.txt',
           'BASELINE.txt','SERVICES.txt')
    def __init__(self):
        os.umask(0o077)
        LOGROOT.mkdir(0o700,parents=True,exist_ok=True)
        os.chmod(LOGROOT,0o700)
        nums=[int(x.name) for x in LOGROOT.iterdir()
              if x.is_dir() and x.name.isdigit()]
        self.run=max(nums,default=0)+1
        self.dir=LOGROOT/str(self.run);self.dir.mkdir(0o700)
        self.p={n:self.dir/n for n in self.names}
        for p in self.p.values():p.touch(0o600);os.chmod(p,0o600)
        self.set('BASELINE.txt',title('CCDC ZERO-HOUR BASELINE')+
                 f'Run: {self.run}\n{SIGNATURE}\n\n')
        self.set('SERVICES.txt',title('CCDC CONFIRMED SERVICES AND LISTENERS')+
                 f'Run: {self.run}\n{SIGNATURE}\n\n')
        self.set('CHANGES.txt',title('CCDC CHANGES AND MANUAL COMMANDS')+
                 f'Run: {self.run}\n{SIGNATURE}\n\n')
        self.set('ERRORS.txt',title('CCDC EXECUTION ERRORS')+
                 f'Run: {self.run}\nTotal errors: 0\n\n'
                 'NO EXECUTION ERRORS RECORDED\n')
        self.set('TODO.txt',title('CCDC THREAT-HUNTING TODO')+
                 f'Run: {self.run}\nPossible threat findings: 0\n\n'
                 'NO AUTOMATED THREAT FINDINGS RECORDED\n')
    def set(self,n,text):
        self.p[n].write_text(text,encoding='utf-8');os.chmod(self.p[n],0o600)
    def add(self,n,text):
        with self.p[n].open('a',encoding='utf-8') as f:f.write(text)
L:Logs

def title(text):return '='*72+'\n'+text+'\n'+'='*72+'\n\n'
def rule():return '-'*72+'\n'
def banner(text):print('\n'+'='*72+'\n'+text+'\n'+'='*72)
def pause(text='>>> TAKE SCREENSHOT NOW <<<'):
    print('\n'+text+'\n');input('Press ENTER to continue...')
def rc_menu(msg):
    while True:
        print('\n'+msg);c=input('[R] Retry  [S] Skip  [Q] Quit: ').strip().lower()
        if c in ('r','s','q'):return c

def wrap_text(text,width=70,indent='  '):
    import textwrap
    return '\n'.join(textwrap.fill(str(text),width=width,
        initial_indent=indent,subsequent_indent=indent).splitlines())
def fields(items):
    out=[]
    for label,value in items:
        out.append(f'{label}:')
        if isinstance(value,(list,tuple)):
            out.extend('  '+str(x) for x in value)
        else:out.append(wrap_text(value))
        out.append('')
    return '\n'.join(out)
def redact(text):
    out=text or ''
    for secret in {PASSWORD,*PASSWORDS.values()}:
        if secret:out=out.replace(secret,'[REDACTED]')
    return out.replace('\x00','')[-16000:]
def proc(argv,inp=None,env=None,timeout=90):
    try:
        p=subprocess.run(argv,input=inp,text=True,capture_output=True,
                         env=env,timeout=timeout)
        return p.returncode,redact(p.stdout),redact(p.stderr)
    except subprocess.TimeoutExpired as exc:
        return 124,redact(exc.stdout),f'TIMEOUT after {timeout}s'
    except Exception as exc:return 125,'',f'{type(exc).__name__}: {exc}'
def _remote_proc(t,remote_command,stdin_text='',timeout=90,tty=False):
    secret=PASSWORDS.get(t.key,PASSWORD)
    env=os.environ.copy();env['SSHPASS']=secret
    tty_args=['-tt'] if tty else []
    return proc(['sshpass','-e','ssh',*tty_args,*SSHOPTS,
                 f'{ADMIN}@{t.ip}',remote_command],
                stdin_text,env,timeout)

def run(t,script,timeout=90,tty=False):
    """Authenticate sudo separately, then send only code to bash stdin."""
    secret=PASSWORDS.get(t.key,PASSWORD)
    if t.local:
        q,o,e=proc(['sudo','-k','-S','-p','','-v'],secret+'\n',timeout=30)
        if q:return q,o,e
        return proc(['sudo','-n','bash','-s'],script,timeout=timeout)
    q,o,e=_remote_proc(t,"sudo -k; sudo -S -p '' -v",secret+'\n',30,tty)
    if q:return q,o,e
    return _remote_proc(t,'sudo -n bash -s',script,timeout,tty)

def run_tty(t,script,timeout=90):
    q,o,e=run(t,script,timeout)
    if (not t.local) and 'must have a tty' in (o+'\n'+e).lower():
        banner('REMOTE SUDO REQUIRES A TTY')
        print(f'Host: {t.label} | {t.ip}')
        c=input('[Y] Retry with SSH -tt  [S] Skip  [Q] Quit: ').strip().lower()
        if c=='q':raise KeyboardInterrupt
        if c!='y':t.active=False;t.skipped=True;return 130,'','Skipped'
        return run(t,script,timeout,tty=True)
    return q,o,e

def error(t,stage,why,operation='Unknown',state='Not available',continued='YES'):
    rec={'stage':stage,'operation':operation,'reason':redact(why).strip(),
         'state':state,'continued':continued}
    t.errors.append(f'{stage}: {rec["reason"]}');t.error_records.append(rec)
def todo(t,why,critical=False,kind='POSSIBLE THREAT',account='Not specified',leads=None):
    rec={'critical':critical,'kind':kind,'account':account,'finding':why,
         'leads':leads or [],'action':'None. Evidence preserved for manual investigation.',
         'severity':'CRITICAL' if critical else 'HIGH','containment':'OPEN'}
    t.todos.append(why);t.finding_records.append(rec)
def change(t,action,target,before,after,recovery,verify=None,expected=None,extra=None):
    t.changes+=1;t.change_records.append({'action':action,'target':target,
        'before':before,'after':after,'recovery':recovery,
        'verify':verify or [],'expected':expected or '', 'extra':extra or {}})

def render_records():
    # Rebuild structured files after all hosts complete.
    changes=title('CCDC CHANGES AND MANUAL COMMANDS')+f'Run: {L.run}\n{SIGNATURE}\n'
    total=sum(len(t.change_records) for t in TARGETS)
    changes+=f'Total changes: {total}\n\n'
    n=0
    for t in TARGETS:
        if not t.change_records:continue
        changes+=title(f'HOST: {t.label}')
        for r in t.change_records:
            n+=1;changes+=rule()+f'CHANGE {n}\n'+rule()+'\n'
            changes+=fields([('ACTION',r['action']),('TARGET',r['target']),
                ('BEFORE',r['before']),('AFTER',r['after']),('RESULT','PASS'),
                ('RECOVERY - AUTHORIZED RESTORATION ONLY',r['recovery']),('VERIFY',r['verify'] or ['Not required']),
                ('EXPECTED',r['expected'] or 'Original state restored')])
    L.set('CHANGES.txt',changes)
    errors=title('CCDC EXECUTION ERRORS')+f'Run: {L.run}\n{SIGNATURE}\nTotal errors: '+str(sum(len(t.error_records) for t in TARGETS))+'\n\n'
    if not any(t.error_records for t in TARGETS):errors+='NO EXECUTION ERRORS RECORDED\n'
    else:
        n=0
        for t in TARGETS:
            if not t.error_records:continue
            errors+=title(f'HOST: {t.label}')
            for r in t.error_records:
                n+=1;errors+=rule()+f'ERROR {n}\n'+rule()+'\n'
                errors+=fields([('PHASE',r['stage']),('OPERATION',r['operation']),
                    ('REASON',r['reason']),('CURRENT STATE',r['state']),
                    ('PROCESSING CONTINUED',r['continued'])])
    L.set('ERRORS.txt',errors)
    findings=title('CCDC THREAT-HUNTING TODO')+f'Run: {L.run}\n{SIGNATURE}\nPossible threat findings: '+str(sum(len(t.finding_records) for t in TARGETS))+'\n\n'
    if not any(t.finding_records for t in TARGETS):findings+='NO AUTOMATED THREAT FINDINGS RECORDED\n'
    else:
        n=0
        for t in TARGETS:
            if not t.finding_records:continue
            findings+=title(f'[!] HOST: {t.label}')
            for r in t.finding_records:
                n+=1;findings+=rule()+f'[ ] FINDING {n} - {r["kind"]}\n'+rule()+'\n'
                findings+=fields([('ACCOUNT / PRINCIPAL',r['account']),
                    ('SEVERITY',r.get('severity','HIGH')),('CONTAINMENT STATUS',r.get('containment','OPEN')),('FINDING',r['finding']),('AUTOMATED ACTION',r.get('action','None. Evidence preserved for manual investigation.')),
                    ('INVESTIGATION LEADS',r['leads'] or ['Review host manually'])])
    L.set('TODO.txt',findings)
def acquire_lock():
    global LOCK_HANDLE
    LOCK_HANDLE=LOCKFILE.open('w')
    try: fcntl.flock(LOCK_HANDLE.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise SystemExit('HARDENING SCRIPT ALREADY RUNNING. This copy made no changes.')
    LOCK_HANDLE.write(f'pid={os.getpid()} started={dt.datetime.now().isoformat()}\n');LOCK_HANDLE.flush()

def partial_change(t,item,before,after,succeeded,failed,finish_cmd,restore_cmd,detail):
    t.partials+=1
    error(t,'UNUSED SERVICES',f'{item}: {failed}; {detail}')
    L.add('CHANGES.txt',f'HOST: {t.label}\nACTION: PARTIAL SERVICE CHANGE\nTARGET: {item}\nBEFORE: {before}\nAFTER: {after}\nSUCCEEDED: {succeeded}\nFAILED: {failed}\nRESULT: PARTIAL - MANUAL REVIEW\nCOMPLETE INTENDED HARDENING:\n{finish_cmd}\nRESTORE ORIGINAL STATE:\n{restore_cmd}\n'+('-'*72)+'\n')
    banner('PARTIAL CHANGE - MANUAL REVIEW REQUIRED')
    print(f'Host: {t.label}\nItem: {item}\nSucceeded: {succeeded}\nFailed: {failed}\nRemaining services will continue.\nREVIEW ERRORS.txt AND CHANGES.txt')
    pause('>>> TAKE SCREENSHOT - REVIEW CHANGES.txt <<<')

def preflight():
    banner('PHASE 0 - PREFLIGHT')
    if getpass.getuser()!=ADMIN or os.geteuid()==0: raise SystemExit('Run as the non-root sysadmin account.')
    miss=[x for x in ('ssh','sudo','bash','sshpass') if not shutil.which(x)]
    if 'sshpass' in miss and shutil.which('apt-get'):
        print('sshpass is missing from the local Ubuntu workstation.')
        if input('[Y] Install with apt  [Q] Quit: ').strip().lower()=='y':
            q,o,e=proc(['sudo','apt-get','update'],timeout=240)
            if q==0:q,o2,e2=proc(['sudo','apt-get','install','-y','sshpass'],timeout=240);o+=o2;e+=e2
            if q==0 and shutil.which('sshpass'):miss.remove('sshpass')
            else:print(redact(o+'\n'+e))
        else:raise SystemExit('sshpass was not installed.')
    if miss: raise SystemExit('Missing dependencies: '+', '.join(miss))
    print('Dependencies ........ PASS')

def verify(t):
    global PASSWORDS
    script="""set -u
printf 'HOST=%s\\n' "$(hostname -f 2>/dev/null || hostname)"
printf 'OS=%s\\n' "$(. /etc/os-release 2>/dev/null; printf %s "${ID:-unknown}")"
printf 'ADMIN=%s\\n' "$(id sysadmin 2>/dev/null || true)"
printf 'ROOT_EUID=%s\\n' "$(id -u)"
"""
    while True:
        q,o,e=run_tty(t,script,30); a=re.search(r'^ADMIN=(.+)$',o,re.M); root=re.search(r'^ROOT_EUID=0$',o,re.M)
        if q==0 and a and root:
            h=re.search(r'^HOST=(.+)$',o,re.M); z=re.search(r'^OS=(.+)$',o,re.M); t.host=h.group(1) if h else t.label; t.osid=z.group(1) if z else 'unknown'
            print(f'{t.label:<24} LOGIN PASS | SUDO PASS | {t.host} | {t.osid}'); return True
        banner('CONTROL VERIFICATION FAILED - '+t.label); print(redact(e or o) or 'No diagnostic output.')
        c=rc_menu('Repair sysadmin locally, then retry; Skip leaves this host unchanged.')
        if c=='q':raise KeyboardInterrupt
        if c=='r':
            if not t.local:
                p=getpass.getpass('If this host now uses a changed sysadmin password, enter it; otherwise press ENTER: ')
                if p:PASSWORDS[t.key]=p
            continue
        t.active=False;t.skipped=True;error(t,'CONTROL VERIFICATION','failed or manually skipped');return False

def control():
    banner('PHASE 1 - CONTROL VERIFICATION')
    for t in TARGETS:verify(t)
    pause('>>> TAKE SCREENSHOT OF PHASE 1 <<<')

def privilege_baseline():
    banner('PHASE 2 - PRIVILEGE BASELINE')
    script=r'''set -u
printf '%s\n' '--- UID 0 ---';awk -F: '$3==0{print $1" uid="$3" shell="$7}' /etc/passwd
printf '\n%s\n' '--- ESCALATION-CAPABLE GROUPS ---'
for g in root sudo wheel admin lxd docker podman libvirt libvirt-qemu disk kvm;do getent group "$g" 2>/dev/null||true;done
printf '\n%s\n' '--- ACTIVE SUDOERS ---'
for f in /etc/sudoers /etc/sudoers.d/*;do [ -f "$f" ]||continue;echo "FILE=$f";grep -nEv '^[[:space:]]*(#|$)' "$f"||true;echo;done
printf '%s\n' '--- INTERACTIVE USERS ---';awk -F: '$7!~/(nologin|false)$/{print $1" uid="$3" shell="$7}' /etc/passwd
printf '\n%s\n' '--- LOGGED IN ---';who||true
'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script)
        block=title(f'1. PRIVILEGE BASELINE - {t.label}')+o.strip()+'\n\n'
        print('\n'+o.strip());L.add('BASELINE.txt',block)
        if q:error(t,'Phase 2 - Privilege Baseline',e or str(q))
    pause('>>> TAKE SCREENSHOT OF PRIVILEGE BASELINE <<<')
def privilege_enforce():
    banner('PHASE 3 - STRICT PRIVILEGE ENFORCEMENT')
    dangerous='root sudo wheel admin lxd docker podman libvirt libvirt-qemu disk kvm'
    script=rf'''set -u;export LC_ALL=C;ADMIN=sysadmin
command -v visudo >/dev/null||{{ echo 'HARDFAIL|VISUDO|missing';exit 40;}}
visudo -c >/dev/null||{{ echo 'HARDFAIL|VISUDO|preexisting invalid';exit 41;}}
B=/var/backups/ccdc-hardening/$(date +%Y%m%d_%H%M%S)-sudo;mkdir -p "$B";chmod 700 "$B";cp -a /etc/sudoers "$B/";[ -d /etc/sudoers.d ]&&cp -a /etc/sudoers.d "$B/"
A=/etc/sudoers.d/00-ccdc-sysadmin;printf 'sysadmin ALL=(ALL:ALL) ALL\n' >"$A";chown root:root "$A";chmod 440 "$A"
visudo -c >/dev/null||{{ echo 'HARDFAIL|SYSADMIN_RULE|invalid';exit 42;}}
for g in {dangerous};do
 row=$(getent group "$g" 2>/dev/null||true);[ -n "$row" ]||continue
 IFS=, read -ra M <<<"${{row##*:}}"
 for u in "${{M[@]}}";do
  u=$(echo "$u"|xargs);[ -n "$u" ]||continue;keep=no
  [ "$g" = root ]&&[ "$u" = root ]&&keep=yes
  {{ [ "$g" = sudo ]||[ "$g" = wheel ];}}&&[ "$u" = "$ADMIN" ]&&keep=yes
  [ "$keep" = yes ]&&continue
  gpasswd -d "$u" "$g" >/dev/null 2>&1&&echo "CHANGED|GROUP|$u|$g"||echo "FAILED|GROUP|$u|$g"
 done
done
for f in /etc/sudoers /etc/sudoers.d/*;do [ -f "$f" ]||continue;[ "$f" = "$A" ]&&continue;tmp=$(mktemp);fc=0
 while IFS= read -r line||[ -n "$line" ];do x=$(echo "$line"|sed 's/^[[:space:]]*//');first=$(echo "$x"|awk '{{print $1}}');case "$x" in ''|'#'*|'Defaults'*|'@include'*|'@includedir'*|'User_Alias'*|'Runas_Alias'*|'Host_Alias'*|'Cmnd_Alias'*)echo "$line">>"$tmp";continue;;esac;case "$first" in root|sysadmin|%sudo|%wheel)echo "$line">>"$tmp";continue;;esac;echo "# CCDC-DISABLED: $line">>"$tmp";echo "CHANGED|SUDOERS|$first|$f|$line";fc=1;done<"$f"
 if [ $fc -eq 1 ];then chown --reference="$f" "$tmp";chmod --reference="$f" "$tmp";visudo -c -f "$tmp" >/dev/null&&cat "$tmp">"$f"||echo "FAILED|TEMP_VISUDO|$f";fi;rm -f "$tmp"
done
visudo -c >/dev/null||{{ echo 'HARDFAIL|VISUDO|post-change invalid';exit 43;}}
while IFS=: read -r u _ _ _ _ _ shell;do case "$shell" in */nologin|*/false)continue;;esac
 if sudo -l -U "$u" </dev/null 2>&1|grep -qE 'may run the following commands|ALL';then [ "$u" = root ]||[ "$u" = sysadmin ]||echo "VERIFY|UNAUTHORIZED|$u";fi
done</etc/passwd
awk -F: '$3==0&&$1!="root"{{print "CRITICAL|UID0|"$1}}' /etc/passwd
'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script,150);removed=[];rules=[];fail=[]
        for line in o.splitlines():
            p=line.split('|')
            if len(p)>=4 and p[:2]==['CHANGED','GROUP']:
                user,group=p[2],p[3];removed.append(f'{user} from {group}');t.revoked_users.add(user)
                change(t,'Removed unauthorized escalation-capable membership',user,
                    f'Member of {group}',f'Removed from {group}',
                    [f'sudo usermod -aG {group} {user}'],
                    [f'id {user}',f'sudo -l -U {user}'],f'Membership in {group} restored')
                todo(t,f'{user} held escalation-capable group membership in {group}; access was revoked.',kind='UNAUTHORIZED PRIVILEGE MEMBERSHIP',account=user,leads=[f'id {user}',f'sudo -l -U {user}',f'getent group {group}',f'ps -u {user} -f'])
                t.finding_records[-1]['action']=f'Removed {user} from {group}.';t.finding_records[-1]['containment']='ACCESS REVOKED; INVESTIGATION OPEN'
            elif len(p)>=5 and p[:2]==['CHANGED','SUDOERS']:
                principal,path,original=p[2],p[3],p[4];rules.append(f'{principal} in {path}')
                change(t,'Disabled unauthorized sudoers rule',principal,
                    original,f'# CCDC-DISABLED: {original}',
                    ['sudo visudo','Restore only the recorded original rule'],
                    ['sudo visudo -c'],original)
                todo(t,f'Unauthorized sudoers principal {principal} was active in {path}; rule disabled.',kind='UNAUTHORIZED SUDOERS RULE',account=principal,leads=[f"sudo grep -R -n '{principal}' /etc/sudoers /etc/sudoers.d",'sudo visudo -c'])
                t.finding_records[-1]['action']=f'Disabled {principal} in {path} using the CCDC-DISABLED marker.';t.finding_records[-1]['containment']='RULE DISABLED; INVESTIGATION OPEN'
            elif len(p)>=3 and p[:2]==['VERIFY','UNAUTHORIZED']:
                fail.append(p[2]);error(t,'Phase 3 - Privilege Enforcement',f'{p[2]} still retains effective sudo',operation='Post-remediation verification',continued='NO');todo(t,f'CRITICAL: {p[2]} retained effective sudo after remediation.',True,'RESIDUAL ADMINISTRATIVE ACCESS',p[2],[f'sudo -l -U {p[2]}'])
            elif len(p)>=3 and p[:2]==['CRITICAL','UID0']:
                todo(t,f'Unexpected UID 0 account {p[2]} requires immediate manual investigation.',True,'UNEXPECTED UID 0 ACCOUNT',p[2],[f'id {p[2]}',f'find / -xdev -uid 0 -ls'])
            elif p and p[0] in ('FAILED','HARDFAIL'):
                fail.append(line);error(t,'Phase 3 - Privilege Enforcement',line,operation='Privilege removal',continued='NO' if p[0]=='HARDFAIL' else 'YES')
        print(f'\n--- {t.label} | PRIVILEGE ENFORCEMENT SUMMARY ---')
        print(f'Group memberships revoked: {len(removed)}')
        for x in removed:print('  '+x)
        print(f'Sudoers rules disabled: {len(rules)}')
        for x in rules:print('  '+x)
        print(f'Failed or residual routes: {len(fail)}')
        print('Result: '+('COMPLETED WITH ERRORS' if fail or q else 'PASS WITH FINDINGS' if removed or rules else 'PASS'))
        if q:error(t,'Phase 3 - Privilege Enforcement',e or o or str(q),continued='NO')
def _section(text,start,end=None):
    try: body=text.split(start,1)[1]
    except IndexError:return ''
    if end and end in body:body=body.split(end,1)[0]
    return body.strip()

def parse_ss_listener(row):
    """Best-effort parser. An unusual ss line must never stop hardening."""
    parts=row.split()
    protocol=parts[0].upper() if parts else 'UNKNOWN'
    endpoint=parts[4] if len(parts)>4 else 'unavailable'
    pid_match=re.search(r'pid=(\d+)',row)
    process_match=re.search(r'users:\(\("([^"]+)"',row)
    return {
        'protocol':protocol,
        'endpoint':endpoint,
        'process':process_match.group(1) if process_match else 'unavailable',
        'pid':pid_match.group(1) if pid_match else 'unavailable',
    }

def services():
    banner('PHASE 4 - SERVICE DISCOVERY')
    script=r"""echo 'RUNNING SERVICE UNITS'
systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort -u
echo 'ENABLED SERVICE UNITS'
systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort -u
echo 'FAILED UNITS'
systemctl --failed --no-legend --no-pager 2>/dev/null || true
echo 'LISTENERS'
if command -v ss >/dev/null 2>&1; then
  ss -H -tulpn 2>/dev/null || true
else
  echo "ss unavailable"
fi
"""
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script)
        running=[x for x in _section(o,'RUNNING SERVICE UNITS','ENABLED SERVICE UNITS').splitlines() if x.strip()]
        enabled=[x for x in _section(o,'ENABLED SERVICE UNITS','FAILED UNITS').splitlines() if x.strip()]
        failed=[x for x in _section(o,'FAILED UNITS','LISTENERS').splitlines() if x.strip() and '0 loaded units listed' not in x]
        listeners=[x for x in _section(o,'LISTENERS').splitlines() if x.strip() and x.strip()!='ss unavailable']
        t.running_count=len(running);t.enabled_count=len(enabled);t.service_count=len(set(running+enabled));t.listener_count=len(listeners);t.failed_units=len(failed)
        doc=title(f'HOST: {t.label}\nHOSTNAME: {t.host}')
        doc+=fields([('Unique running/enabled services',str(t.service_count)),('Running services',str(t.running_count)),('Enabled services',str(t.enabled_count)),('Failed units',str(t.failed_units)),('Listening sockets',str(t.listener_count))])
        doc+=title('RUNNING SERVICE UNITS')+'\n'.join(running or ['None'])+'\n\n'
        doc+=title('ENABLED SERVICE UNITS')+'\n'.join(enabled or ['None'])+'\n\n'
        doc+=title('[!] FAILED UNITS - MANUAL REVIEW REQUIRED' if failed else 'FAILED UNITS')
        if failed:
            for i,row in enumerate(failed,1):
                unit=row.split()[0];doc+=fields([(f'FAILED UNIT {i}',row),('REVIEW',[f'systemctl status {unit} --no-pager -l',f'journalctl -u {unit} --no-pager -n 50',f'systemctl is-enabled {unit}'])])
        else:doc+='No failed units found.\n\n'
        doc+=title('LISTENING PORTS')
        if listeners:
            for i,row in enumerate(listeners,1):
                parsed=parse_ss_listener(row)
                doc+=fields([(f'LISTENER {i}',parsed['protocol']),
                    ('LOCAL ENDPOINT',parsed['endpoint']),
                    ('PROCESS',parsed['process']),('PID',parsed['pid'])])
        else:doc+='No listeners observed.\n'
        L.add('SERVICES.txt',doc)
        print(f'\n--- {t.label} | SERVICE AND LISTENER SUMMARY ---')
        print(f'Running services: {t.running_count}\nEnabled services: {t.enabled_count}\nUnique services: {t.service_count}\nListeners: {t.listener_count}\nFailed units: {t.failed_units}')
        if failed:print('[!] Manual review required in SERVICES.txt')
        if q:error(t,'Phase 4 - Service Discovery',e or str(q),operation='Collect running/enabled services, failed units, and listeners',state='Phase returned nonzero; evidence may be incomplete',continued='YES')

def ssh_phase():
    banner('PHASE 5 - TRANSACTIONAL SSH HARDENING')
    s=r'''set -u;B=/var/backups/ccdc-hardening/$(date +%Y%m%d_%H%M%S)-ssh;mkdir -p "$B";chmod 700 "$B"
SSHD=$(command -v sshd 2>/dev/null||true);[ -n "$SSHD" ]||SSHD=/usr/sbin/sshd;[ -x "$SSHD" ]||{ echo 'SKIP|SSH|not installed';exit 0;}
if systemctl list-unit-files ssh.service 2>/dev/null|grep -q ssh.service;then S=ssh;elif systemctl list-unit-files sshd.service 2>/dev/null|grep -q sshd.service;then S=sshd;else echo 'FAILED|SSH_UNIT|undetected';exit 22;fi
BR=$($SSHD -T|awk '$1=="permitrootlogin"{print $2;exit}');BM=$($SSHD -T|awk '$1=="maxauthtries"{print $2;exit}')
D=/etc/ssh/sshd_config.d/99-ccdc-hardening.conf;mkdir -p /etc/ssh/sshd_config.d;[ -e "$D" ]&&cp -a "$D" "$B/before.conf"
printf '# CCDC V3.2.1\nPermitRootLogin no\nMaxAuthTries 3\n'>"$D";chmod 600 "$D"
if ! $SSHD -t 2>"$B/error";then [ -e "$B/before.conf" ]&&cp -a "$B/before.conf" "$D"||rm -f "$D";echo "FAILED|SSHD_VALIDATE|$(cat "$B/error")";exit 20;fi
systemctl reload "$S"||{ echo "FAILED|RELOAD|$S";exit 21;}
AR=$($SSHD -T|awk '$1=="permitrootlogin"{print $2;exit}');AM=$($SSHD -T|awk '$1=="maxauthtries"{print $2;exit}')
echo "RESULT|$BR|$BM|$AR|$AM|$S|$D";[ "$AR" = no ]&&[ "$AM" = 3 ]
'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,s);print('\n--- '+t.label+' ---');m=re.search(r'RESULT\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)',o)
        if q==0 and m:
            br,bm,ar,am,unit,path=m.groups();change(t,'SSH_CONFIGURATION',path,f'PermitRootLogin={br}; MaxAuthTries={bm}',f'PermitRootLogin={ar}; MaxAuthTries={am}',f'Restore BEFORE values; sudo sshd -t; sudo systemctl reload {unit}')
            if not verify(t):error(t,'SSH POST-VERIFY','sysadmin reauthentication failed')
        elif 'SKIP|SSH|' in o:
            t.ssh_status='NOT APPLICABLE - SSH SERVER NOT INSTALLED';print('OpenSSH server installed: NO\nChanges made: NONE\nRoot SSH verification: NOT TESTED\nResult: NOT APPLICABLE')
        else:
            error(t,'SSH HARDENING',e or o)
            c=rc_menu(t.label+': SSH hardening failed. Repair, retry, skip, or quit.')
            if c=='q':raise KeyboardInterrupt
            if c=='r':
                q2,o2,e2=run(t,s);print(o2 or e2)
                if q2:error(t,'SSH HARDENING RETRY',e2 or o2);t.active=False
            else:t.active=False
    pause('>>> TAKE SCREENSHOT OF PHASES 3-5 <<<')

def permissions():
    banner('PHASE 6 - CRITICAL FILE PERMISSIONS')
    s=r'''set -u
fix(){ p=$1;o=$2;g=$3;m=$4;[ -e "$p" ]||{ echo "SKIP|$p";return;};b=$(stat -c '%U:%G %a' "$p");chown "$o:$g" "$p";chmod "$m" "$p";a=$(stat -c '%U:%G %a' "$p");[ "$a" = "$b" ]&&echo "UNCHANGED|$p|$a"||echo "CHANGED|$p|$b|$a";}
sg=root;getent group shadow >/dev/null&&sg=shadow
fix /etc/passwd root root 644;fix /etc/group root root 644;fix /etc/shadow root "$sg" 640;fix /etc/gshadow root "$sg" 640;fix /etc/sudoers root root 440
for f in /etc/sudoers.d/*;do [ -f "$f" ]&&fix "$f" root root 440;done
command -v visudo >/dev/null&&visudo -c >/dev/null||true
'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,s);print('\n--- '+t.label+' ---')
        for visible in [x for x in o.splitlines() if x.startswith(('CHANGED|','FAILED|'))]:print(visible)
        for line in o.splitlines():
            p=line.split('|')
            if len(p)>=4 and p[0]=='CHANGED':
                owner,mode=p[2].split();change(t,'Corrected critical file ownership or permissions',p[1],p[2],p[3],[f'sudo chown {owner} {p[1]}',f'sudo chmod {mode} {p[1]}'],[f'stat -c "%U:%G %a %n" {p[1]}'],p[2])
        checked=len([x for x in o.splitlines() if x.startswith(('UNCHANGED|','CHANGED|'))]);changed=len([x for x in o.splitlines() if x.startswith('CHANGED|')]);print(f'Files checked: {checked}\nAlready correct: {checked-changed}\nCorrected: {changed}\nResult: '+('PASS' if not q else 'COMPLETED WITH ERRORS'))
        if q:error(t,'FILE PERMISSIONS',e or str(q))

def sysctl_phase():
    banner('PHASE 7 - SUID CORE-DUMP HARDENING')
    script=r'''set -u
F=/etc/sysctl.d/99-ccdc-hardening.conf
BD=/var/backups/ccdc-hardening/$(date +%Y%m%d_%H%M%S)-sysctl
mkdir -p "$BD";chmod 700 "$BD"
B=$(sysctl -n fs.suid_dumpable 2>/dev/null||echo unknown)
EXISTED=no
[ -e "$F" ]&&{ EXISTED=yes;cp -a "$F" "$BD/before.conf";}
if grep -qE '^[[:space:]]*fs\.suid_dumpable[[:space:]]*=' "$F" 2>/dev/null;then
 sed -i 's/^[[:space:]]*fs\.suid_dumpable[[:space:]]*=.*/fs.suid_dumpable = 0/' "$F"
else printf '\n# CCDC V3.2.1\nfs.suid_dumpable = 0\n' >>"$F";fi
chmod 600 "$F";sysctl -w fs.suid_dumpable=0 >/dev/null
A=$(sysctl -n fs.suid_dumpable)
echo "RESULT|$B|$A|$F|$EXISTED|$BD";[ "$A" = 0 ]
'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script);m=re.search(r'RESULT\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)',o)
        if q==0 and m and m.group(1)!=m.group(2):
            before,after,path,existed,backup=m.groups()
            if existed=='yes':
                recovery=[f'sudo cp {backup}/before.conf {path}','sudo sysctl --system']
                expected='Original configuration file and runtime value restored'
            else:
                recovery=[f'sudo rm -f {path}',f'sudo sysctl -w fs.suid_dumpable={before}']
                expected=f'fs.suid_dumpable = {before}; V3.2.1 file absent'
            change(t,'Hardened kernel setting','fs.suid_dumpable',before,after,recovery,['sysctl fs.suid_dumpable'],expected,{'original_file_existed':existed,'backup':backup})
            print(f'Setting: fs.suid_dumpable\nPrevious value: {before}\nNew value: {after}\nPersistent file: {path}\nResult: PASS')
        elif q:error(t,'Phase 7 - SUID Core-Dump Hardening',e or o,operation='Set fs.suid_dumpable to 0',continued='YES')
def service_recovery(unit,active,enabled):
    commands=[]
    if enabled in ('enabled','enabled-runtime'):
        commands.append(f'sudo systemctl enable {unit}')
    elif enabled=='masked':
        commands.append(f'sudo systemctl mask {unit}')
    else:
        commands.append(f'sudo systemctl disable {unit}')
    commands.append(f'sudo systemctl {"start" if active=="active" else "stop"} {unit}')
    return commands

def service_verify(unit):
    return [f'systemctl is-active {unit}',f'systemctl is-enabled {unit}']

def unused_services():
    banner('PHASE 8 - APPROVED UNUSED SERVICES');print('Allowlist: Avahi, CUPS, Bluetooth, ModemManager')
    units=' '.join(shlex.quote(x) for x in UNUSED)
    script=f'''set -u
for u in {units};do load=$(systemctl show -p LoadState --value "$u" 2>/dev/null||true);if [ "$load" = not-found ]||[ -z "$load" ];then echo "NOT_PRESENT|$u";continue;fi;a=$(systemctl is-active "$u" 2>/dev/null||true);e=$(systemctl is-enabled "$u" 2>/dev/null||true);if [ "$a" != active ]&&[ "$e" != enabled ]&&[ "$e" != enabled-runtime ];then echo "NO_ACTION|$u|$a|$e";continue;fi;st=NOT_NEEDED;di=NOT_NEEDED;if [ "$a" = active ];then systemctl stop "$u" 2>/tmp/ccdc-st-$$&&st=SUCCESS||st=FAILED;fi;if [ "$e" = enabled ]||[ "$e" = enabled-runtime ];then systemctl disable "$u" 2>/tmp/ccdc-di-$$&&di=SUCCESS||di=FAILED;fi;aa=$(systemctl is-active "$u" 2>/dev/null||true);ee=$(systemctl is-enabled "$u" 2>/dev/null||true);d="stop=$st disable=$di";x=$(cat /tmp/ccdc-st-$$ /tmp/ccdc-di-$$ 2>/dev/null|tr '\n' ' ');rm -f /tmp/ccdc-st-$$ /tmp/ccdc-di-$$;if [ "$st" != FAILED ]&&[ "$di" != FAILED ];then echo "CHANGED|$u|$a|$e|$aa|$ee|$d";elif [ "$st" = SUCCESS ]||[ "$di" = SUCCESS ];then echo "PARTIAL|$u|$a|$e|$aa|$ee|$d|$x";else echo "FAILED|$u|$a|$e|$aa|$ee|$d|$x";fi;done'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script,150);present=[];noaction=[];changed_count=0;partial_count=0;failed_count=0
        for line in o.splitlines():
            p=line.split('|');kind=p[0]
            if kind=='NOT_PRESENT':present.append(p[1])
            elif kind=='NO_ACTION':noaction.append(p[1])
            elif kind=='CHANGED' and len(p)>=7:
                changed_count+=1
                u,ba,be,aa,ae,d=p[1:7];change(t,'Disabled approved unused service',u,f'Runtime state: {ba}; Boot state: {be}',f'Runtime state: {aa}; Boot state: {ae}; {d}',service_recovery(u,ba,be),service_verify(u),f'Runtime state: {ba}; Boot state: {be}')
            elif kind=='PARTIAL' and len(p)>=8:
                partial_count+=1
                u,ba,be,aa,ae,d=p[1:7];finish=f'  sudo systemctl stop {u}\n  sudo systemctl disable {u}';partial_change(t,u,f'active={ba} enabled={be}',f'active={aa} enabled={ae}',d.replace('FAILED','').strip(),d,finish,'\n'.join(service_recovery(u,ba,be)),'|'.join(p[7:]))
            elif kind=='FAILED':
                failed_count+=1
                error(t,'UNUSED SERVICES',line);banner('SERVICE OPERATION FAILED - NO VERIFIED CHANGE');print(f'Host: {t.label}\nService: {p[1] if len(p)>1 else "unknown"}\nReview ERRORS.txt. Remaining services will continue.');pause('>>> TAKE SCREENSHOT OF SERVICE FAILURE <<<')
        print(f'\n--- {t.label} | APPROVED UNUSED SERVICES ---')
        print(f'Not installed: {len(present)}\nAlready inactive/disabled: {len(noaction)}\nChanged: {changed_count}\nPartial operations: {partial_count}\nFailures: {failed_count}')
        if q:error(t,'UNUSED SERVICES',e or str(q))
    pause('>>> TAKE SCREENSHOT OF PHASES 6-8 <<<')

def persistence():
    banner('PHASE 9 - PERSISTENCE BASELINE AND CORRELATION')
    script=r'''set -u
printf '%s\n' META_BEGIN
for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*;do
 [ -f "$f" ]||continue;owner=$(stat -c '%U:%G' "$f");mode=$(stat -c '%a' "$f");hash=$(sha256sum "$f"|awk '{print $1}');pkg=$(dpkg -S "$f" 2>/dev/null|head -1|cut -d: -f1||rpm -qf "$f" 2>/dev/null||echo unowned);echo "CRONMETA|$f|$owner|$mode|$pkg|$hash";done
printf '%s\n' HIGH_RISK_CONTENT_BEGIN
for f in /etc/crontab /etc/cron.d/*;do [ -f "$f" ]||continue;echo "FILE=$f";grep -Ev '^[[:space:]]*(#|$)' "$f"||true;done
printf '%s\n' USER_CRON_BEGIN
uc=0
for u in $(awk -F: '$7!~/(nologin|false)$/{print $1}' /etc/passwd);do tab=$(crontab -u "$u" -l 2>/dev/null||true);[ -n "$tab" ]||continue;uc=$((uc+1));echo "USERCRON|$u|BEGIN";printf '%s\n' "$tab";echo "USERCRON|$u|END";done
echo "COUNT|USER_CRONTABS|$uc"
printf '%s\n' TIMERS_BEGIN
while read -r timer;do [ -n "$timer" ]||continue;svc=$(systemctl show "$timer" -p Triggers --value 2>/dev/null|awk '{print $1}');[ -n "$svc" ]||continue;pid=$(systemctl show "$svc" -p MainPID --value);usr=$(systemctl show "$svc" -p User --value);state=$(systemctl show "$svc" -p ActiveState --value);frag=$(systemctl show "$svc" -p FragmentPath --value);execs=$(systemctl show "$svc" -p ExecStart --value|sed -E 's/.*path=([^ ;}]+).*/\1/');echo "TIMER|$timer|$svc|${pid:-0}|${usr:-root}|$state|$frag|$execs";done < <(systemctl list-timers --all --no-legend --no-pager 2>/dev/null|awk '{print $(NF-1)}'|sort -u)
printf '%s\n' AT_BEGIN;if command -v atq >/dev/null;then atout=$(atq 2>/dev/null||true);[ -n "$atout" ]&&printf '%s\n' "$atout"||echo AT_QUEUE_EMPTY;else echo ATQ_UNAVAILABLE;fi
printf '%s\n' RC_LOCAL_BEGIN;[ -e /etc/rc.local ]&&cat /etc/rc.local||echo ABSENT
printf '%s\n' ESCALATION_BEGIN
while IFS= read -r line;do [ -n "$line" ]||continue;path=${line%% *};caps=${line#* };owner=$(stat -c '%U:%G' "$path" 2>/dev/null||echo unknown);mode=$(stat -c '%a' "$path" 2>/dev/null||echo unknown);pkg=$(dpkg -S "$path" 2>/dev/null|head -1|cut -d: -f1||rpm -qf "$path" 2>/dev/null||echo unowned);echo "CAP|$path|$caps|$owner|$mode|$pkg";done < <(getcap -r / 2>/dev/null|grep -E 'cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|net_admin|sys_ptrace)'||true)
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf 'SUIDSGID|%m|%u:%g|%p\n' 2>/dev/null|head -300
for p in /var/run/docker.sock /run/podman/podman.sock /var/snap/lxd/common/lxd/unix.socket /var/run/libvirt/libvirt-sock;do [ -e "$p" ]&&stat -c 'SOCKET|%n|%U:%G|%a' "$p";done
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys;do [ -f "$f" ]||continue;active=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null||true);owner=$(stat -c '%U:%G' "$f");mode=$(stat -c '%a' "$f");echo "SSHKEYS|$f|$active|$owner|$mode";done
'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script,180)
        metas=re.findall(r'^CRONMETA\|([^|]+)\|([^|]+)\|(\d+)\|([^|]*)\|([0-9a-f]+)$',o,re.M);t.cron_files=len(metas)
        m=re.search(r'^COUNT\|USER_CRONTABS\|(\d+)$',o,re.M);t.user_crontabs=int(m.group(1)) if m else 0
        timers=re.findall(r'^TIMER\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)$',o,re.M);timers.sort(key=lambda x:(x[2] in ('0',''),x[3] in ('','root'),x[0]));t.timer_count=len(timers);t.timer_pid_count=sum(1 for x in timers if x[2] not in ('0',''))
        cron_users=set(re.findall(r'^USERCRON\|([^|]+)\|BEGIN$',o,re.M));correlated=sorted(cron_users&t.revoked_users)
        base=title(f'2. PERSISTENCE SUMMARY - {t.label}')+f'System cron files: {t.cron_files}\nUser crontabs: {t.user_crontabs}\nSystemd timers: {t.timer_count}\nTimer services with active PIDs: {t.timer_pid_count}\nRevoked-admin users with crontabs: {len(correlated)}\n\n'
        base+=title('3. SYSTEM CRON INVENTORY')
        for i,(path,owner,mode,pkg,hsh) in enumerate(metas,1):base+=f'CRON FILE {i}\n  Path: {path}\n  Owner: {owner}\n  Mode: 0{mode}\n  Package: {pkg or "unowned"}\n  SHA-256:\n    {hsh}\n  Writable by non-root: '+('YES' if int(mode[-1])&2 or int(mode[-2])&2 else 'NO')+'\n\n'
        high=o.split('HIGH_RISK_CONTENT_BEGIN',1)[-1].split('USER_CRON_BEGIN',1)[0].strip();base+=title('4. HIGH-RISK CRON CONTENT')+(high or 'No active entries found.')+'\n\n'
        userpart=o.split('USER_CRON_BEGIN',1)[-1].split('TIMERS_BEGIN',1)[0];userlines=[x for x in userpart.splitlines() if not x.startswith('COUNT|')];base+=title('5. USER CRONTABS')+('\n'.join(userlines).strip() or 'No personal user crontabs found.')+'\n\n'
        base+=title('6. SYSTEMD TIMER INVENTORY')
        for i,(timer,svc,pid,usr,state,frag,exe) in enumerate(timers,1):base+=rule()+f'TIMER {i}\n'+rule()+f'Timer: {timer}\nActivates: {svc}\nUser: {usr or "root"}'+(' [NON-ROOT SERVICE ACCOUNT]' if usr not in ('','root') else '')+f'\nState: {state}\nMain PID: {pid}\nExecutable: {exe}\nUnit: {frag}\n\n'
        at=o.split('AT_BEGIN',1)[-1].split('RC_LOCAL_BEGIN',1)[0].strip();attext='atq command available: NO\nQueued jobs: NOT CHECKED' if at=='ATQ_UNAVAILABLE' else 'atq command available: YES\nQueued jobs: 0' if at=='AT_QUEUE_EMPTY' else 'atq command available: YES\n'+at
        rc=o.split('RC_LOCAL_BEGIN',1)[-1].split('ESCALATION_BEGIN',1)[0].strip();rctext='Path: /etc/rc.local\nPresent: NO' if rc=='ABSENT' else 'Path: /etc/rc.local\nPresent: YES\n'+rc
        esc=o.split('ESCALATION_BEGIN',1)[-1].strip();base+=title('7. AT QUEUE')+attext+'\n\n'+title('8. RC.LOCAL')+rctext+'\n\n'+title('9. ESCALATION-SURFACE INVENTORY')
        caps=re.findall(r'^CAP\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)$',esc,re.M);suid=[x for x in esc.splitlines() if x.startswith('SUIDSGID|')];sockets=re.findall(r'^SOCKET\|([^|]+)\|([^|]+)\|([^|]+)$',esc,re.M);keys=re.findall(r'^SSHKEYS\|([^|]+)\|(\d+)\|([^|]+)\|(\d+)$',esc,re.M)
        base+='--- FILE CAPABILITIES ---\n';
        for path,capsv,owner,mode,pkg in caps:
            packaged=(pkg not in ('','unowned') and owner.split(':')[0]=='root')
            base+=f'Path: {path}\nCapabilities: {capsv}\nOwner: {owner}\nMode: 0{mode}\nPackage: {pkg}\nAutomated threat finding: '+('NO - packaged and root-owned' if packaged else 'REVIEW REQUIRED')+'\n\n'
        if not caps:base+='None found.\n\n'
        base+='--- SUID/SGID FILES ---\nTotal found: '+str(len(suid))+'\n'+ '\n'.join(x.replace('SUIDSGID|','').replace('|','  ',2) for x in suid)+'\n\n'
        base+='--- CONTAINER AND VIRTUALIZATION SOCKETS ---\n';
        for path,owner,mode in sockets:base+=f'Path: {path}\nOwner: {owner}\nMode: {mode}\n\n'
        if not sockets:base+='None found.\n\n'
        base+='--- AUTHORIZED-KEY FILES ---\n';
        for path,count,owner,mode in keys:base+=f'Path: {path}\nActive key entries: {count}\nOwner: {owner}\nMode: 0{mode}\nReview required: '+('NO' if int(count)==0 else 'YES')+'\n\n'
        L.add('BASELINE.txt',base)
        for u in correlated:todo(t,f'{u} had administrative access revoked and owns a personal crontab.',kind='PRIVILEGE AND PERSISTENCE CORRELATION',account=u,leads=[f'sudo crontab -u {u} -l',f'ps -u {u} -f'])
        risky_prefix=('/home/','/tmp/','/var/tmp/','/dev/shm/','/opt/','/usr/local/')
        for path,capsv,owner,mode,pkg in caps:
            highrisk=any(x in capsv for x in ('cap_setuid','cap_setgid','cap_sys_admin'))
            writable=mode.isdigit() and (int(mode[-1])&2 or int(mode[-2])&2)
            if path.startswith(risky_prefix) or owner.split(':')[0]!='root' or writable or pkg in ('','unowned') or highrisk:todo(t,f'Capability requires manual review: {path} {capsv}',kind='POSSIBLE PRIVILEGE ESCALATION SURFACE',leads=[f'getcap {path}',f'stat {path}'])
        for row in suid:
            if any(pfx in row for pfx in ('|/home/','|/tmp/','|/var/tmp/','|/dev/shm/','|/opt/','|/usr/local/')):todo(t,f'Unusual SUID/SGID file: {row}',kind='POSSIBLE PRIVILEGE ESCALATION SURFACE',leads=['Review ownership and package source'])
        for path,owner,mode in sockets:
            unsafe=mode.isdigit() and int(mode[-1])&2
            group=owner.split(':',1)[1] if ':' in owner else ''
            members=(run_tty(t,f'getent group {shlex.quote(group)} 2>/dev/null || true',30)[1].strip().split(':')[-1] if group else '')
            if unsafe or members:todo(t,f'Container socket may remain accessible: {path}; members={members or "none"}',kind='POSSIBLE PRIVILEGE ESCALATION SURFACE',leads=[f'stat {path}',f'getent group {group}'])
        for path,count,owner,mode in keys:
            expected_owner='root' if path.startswith('/root/') else Path(path).parts[2] if len(Path(path).parts)>2 else ''
            unsafe=int(mode[-1])&7 if mode.isdigit() else 1
            if int(count)>0 or owner.split(':')[0]!=expected_owner or unsafe:todo(t,f'Authorized-key file requires review: {path}; active keys={count}; owner={owner}; mode={mode}',kind='SSH AUTHORIZATION REVIEW',leads=[f'sudo cat {path}',f'sudo stat {path}'])
        print(f'\n--- {t.label} | PERSISTENCE SUMMARY ---\nSystem cron files: {t.cron_files}\nUser crontabs: {t.user_crontabs}\nSystemd timers: {t.timer_count}\nTimer services with active PIDs: {t.timer_pid_count}\nRevoked-admin users with crontabs: {len(correlated)}')
        if q:error(t,'Phase 9 - Persistence Baseline',e or str(q),operation='Collect persistence and escalation inventory',state='Evidence may be incomplete',continued='YES')
def finish():
    banner('PHASE 10 - FINAL VERIFICATION')
    script=r'''echo "ROOT_UID=$(id -u root 2>/dev/null||echo missing)";echo "ROOT_GROUP=$(getent group root 2>/dev/null||true)";echo "SUDO=$(getent group sudo 2>/dev/null||true)";echo "WHEEL=$(getent group wheel 2>/dev/null||true)";D=$(command -v sshd 2>/dev/null||true);[ -n "$D" ]||D=/usr/sbin/sshd;if [ -x "$D" ];then echo "PERMIT_ROOT=$($D -T|awk '$1==\"permitrootlogin\"{print $2;exit}')";echo "MAX_TRIES=$($D -T|awk '$1==\"maxauthtries\"{print $2;exit}')";else echo 'SSH_NOT_INSTALLED=1';fi;echo "SUID_DUMPABLE=$(sysctl -n fs.suid_dumpable 2>/dev/null||echo unknown)"'''
    for t in TARGETS:
        if not t.active:continue
        q,o,e=run_tty(t,script)
        vals=dict(re.findall(r'^([A-Z_]+)=(.*)$',o,re.M))
        root_ok=vals.get('ROOT_UID')=='0'
        root_group=vals.get('ROOT_GROUP','')
        sudo_group=vals.get('SUDO','')
        wheel=vals.get('WHEEL','')
        ssh_text='NOT TESTED - OpenSSH server not installed' if vals.get('SSH_NOT_INSTALLED')=='1' else f"PermitRootLogin={vals.get('PERMIT_ROOT','unknown')}; MaxAuthTries={vals.get('MAX_TRIES','unknown')}"
        dump_ok=vals.get('SUID_DUMPABLE')=='0'
        readable=(f"Root UID: {'PASS - root is UID 0' if root_ok else 'FAIL'}\n"
                  f"Root group: {root_group or 'absent'}\n"
                  f"Sudo group: {sudo_group or 'absent'}\n"
                  f"Wheel group: {wheel or 'absent or empty'}\n"
                  f"SSH hardening: {ssh_text}\n"
                  f"SUID core dumps: {'PASS - disabled' if dump_ok else 'FAIL'}")
        print('\n--- '+t.label+' ---\n'+readable)
        L.add('BASELINE.txt',title(f'10. FINAL VERIFICATION - {t.label}')+readable+'\n\n')
        if q:error(t,'Phase 10 - Final Verification',e or str(q))
    render_records()
    lines=title('CCDC LINUX HARDENING V3.2.1 - FINAL SUMMARY')+f'Run: {L.run}\n{SIGNATURE}\nEvidence directory: {L.dir}\n\n'
    for t in TARGETS:
        status='INCOMPLETE - PHASE/HOST SKIPPED' if t.skipped else 'PARTIAL CHANGES - MANUAL REVIEW' if t.partials else 'COMPLETED WITH ERRORS' if t.errors else 'PASS WITH FINDINGS' if t.todos else 'PASS'
        lines+=title(f'HOST: {t.label}\nTARGET: {t.ip or "local"}')
        lines+=f'Final status: {status}\n\nRecorded changes: {t.changes}\nPossible threat findings: {len(t.todos)}\nExecution errors: {len(t.errors)}\nPartial operations: {t.partials}\n\nServices recorded: {t.service_count}\nListeners recorded: {t.listener_count}\nCron files recorded: {t.cron_files}\nUser crontabs recorded: {t.user_crontabs}\nTimers recorded: {t.timer_count}\n\nSSH hardening: {t.ssh_status}\n\n'
        if t.partials:lines+='ACTION:\n  Review ERRORS.txt and CHANGES.txt.\n\n'
        elif t.errors:lines+='ACTION:\n  Review ERRORS.txt.\n\n'
        if t.todos:lines+=f'THREAT-HUNTING ACTION:\n  Review TODO.txt: {len(t.todos)} possible threats.\n\n'
    lines+=title('SCRIPT SCOPE')+'No accounts were locked or deleted.\nNo firewall, NAT, or routing changes were made.\nNo reboots or shutdowns were performed.\nNo DNS or hostname changes were made.\nNo cron entries were deleted.\nNo processes were terminated.\nSELinux was not modified.\n'
    L.set('SUMMARY.txt',lines)
    pause('>>> TAKE SCREENSHOT OF PHASES 9-10 <<<')

def final_file_status():
    changes=sum(t.changes for t in TARGETS);errors=sum(len(t.errors) for t in TARGETS);findings=sum(len(t.todos) for t in TARGETS);partials=sum(t.partials for t in TARGETS);services=sum(t.service_count for t in TARGETS);listeners=sum(t.listener_count for t in TARGETS)
    print('\nEVIDENCE FILE STATUS')
    print('  BASELINE.txt : CREATED - baseline and persistence recorded')
    print(f'  CHANGES.txt  : CREATED - {changes} change record(s)')
    print(f'  ERRORS.txt   : CREATED - REVIEW {errors} error(s)' if errors else '  ERRORS.txt   : CREATED - no execution errors')
    print(f'  SERVICES.txt : CREATED - {services} services, {listeners} listeners')
    print('  SUMMARY.txt  : CREATED - final run summary recorded')
    print(f'  TODO.txt     : CREATED - REVIEW FINDINGS: {findings} possible threats' if findings else '  TODO.txt     : CREATED - no automated threat findings')
    if partials:print('\nACTION: Review ERRORS.txt and CHANGES.txt.')
    elif errors:print('\nACTION: Review ERRORS.txt.')
    if findings:print(f'\nTHREAT HUNTING: Review TODO.txt ({findings} findings).')
def main():
    global PASSWORD,PASSWORDS,L
    acquire_lock();print('CCDC Linux Hardening V3.2.1 | SAUCE | 11/13/2026')
    PASSWORD=getpass.getpass('Enter the rotated sysadmin password used on all Linux systems: ')
    if not PASSWORD:return 2
    PASSWORDS={t.key:PASSWORD for t in TARGETS}
    L=Logs();print('Protected evidence directory:',L.dir);preflight();control();privilege_baseline();privilege_enforce();services();ssh_phase();permissions();sysctl_phase();unused_services();persistence();finish()
    banner('AUTOMATED ZERO-HOUR HARDENING V3.2.1 COMPLETE');print('Evidence:',L.dir);final_file_status();return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except KeyboardInterrupt:
        msg='SCRIPT INTERRUPTED. Completion may be unverified. Review ERRORS.txt and CHANGES.txt.';print('\n'+msg)
        if 'L' in globals() and hasattr(L,'p'):L.add('ERRORS.txt',msg+'\n');L.add('SUMMARY.txt','\n'+msg+'\n')
        raise SystemExit(130)
    except Exception as exc:
        msg=f'UNHANDLED SCRIPT ERROR: {type(exc).__name__}: {exc}'
        print('\n'+msg)
        if 'L' in globals() and hasattr(L,'p'):
            L.add('ERRORS.txt',msg+'\n')
            L.add('SUMMARY.txt','\n'+msg+'\n')
        raise SystemExit(1)
