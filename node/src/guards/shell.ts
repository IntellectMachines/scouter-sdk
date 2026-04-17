/**
 * ShellGuard — Intercepts shell/subprocess commands before execution.
 * Mirrors sdk/python/scouter/guards/shell_guard.py (30+ regex rules).
 */

import { GuardDecision } from "../models.js";
import { BaseGuard, type GuardRule, type GuardResult } from "./base.js";

export const SHELL_RULES: GuardRule[] = [
  // Destructive
  { name: "rm_rf",           pattern: "\\brm\\s+.*-[a-zA-Z]*r[a-zA-Z]*f|\\brm\\s+.*-[a-zA-Z]*f[a-zA-Z]*r|\\brm\\s+-rf\\b", risk: 95, desc: "Recursive force delete" },
  { name: "rm_root",         pattern: "\\brm\\b.*(?:\\s+/\\s|\\s+/\\*|\\s+~|\\s+\\.\\.\\/)|\\brm\\b.*--no-preserve-root", risk: 100, desc: "Delete targeting root/home/parent" },
  { name: "format_disk",     pattern: "\\b(?:mkfs|format)\\b.*(?:/dev/|[A-Z]:)", risk: 100, desc: "Disk format command" },
  { name: "dd_wipe",         pattern: "\\bdd\\b.*\\bof\\s*=\\s*/dev/(?:sd|hd|nvme|vd)", risk: 95, desc: "dd writing to block device" },
  { name: "shred_wipe",      pattern: "\\b(?:shred|wipe|srm|secure-delete)\\b", risk: 90, desc: "Secure delete/wipe utility" },
  { name: "truncate_dev",    pattern: ">\\s*/dev/(?:sd|hd)|cat\\s+/dev/(?:null|zero|urandom)\\s*>\\s*/", risk: 95, desc: "Overwriting device with /dev/null" },
  // Privilege escalation
  { name: "sudo_su",         pattern: "\\b(?:sudo|su\\s+-|su\\s+root|doas)\\b", risk: 60, desc: "Privilege escalation via sudo/su" },
  { name: "chmod_777",       pattern: "\\bchmod\\b.*(?:777|u\\+s|g\\+s|\\+s|4755|2755)", risk: 75, desc: "Dangerous permissions (777/SUID)" },
  { name: "passwd_shadow",   pattern: "\\b(?:cat|less|more|head|tail|vi|vim|nano)\\b.*(?:/etc/passwd|/etc/shadow)", risk: 80, desc: "Reading password/shadow files" },
  // Data exfiltration
  { name: "curl_post",       pattern: "\\bcurl\\b.*(?:-d\\b|-X\\s*POST|--data).*(?:http|https)", risk: 70, desc: "curl POSTing data externally" },
  { name: "wget_pipe_exec",  pattern: "\\bwget\\b.*-O\\s*-\\s*\\||\\bcurl\\b.*\\|\\s*(?:bash|sh|python|perl|ruby)", risk: 90, desc: "Download and pipe to interpreter" },
  { name: "netcat",          pattern: "\\b(?:nc|ncat|netcat)\\b.*(?:-l|-e\\s*/bin|mkfifo)", risk: 90, desc: "Netcat listener/reverse shell" },
  { name: "exfil_encode",    pattern: "\\bbase64\\b.*\\|\\s*(?:curl|wget|nc)", risk: 85, desc: "Encoding + sending to external host" },
  // Reverse shells
  { name: "bash_revshell",   pattern: "(?:bash|sh)\\s+-i\\s*>(?:&|\\s)\\s*/dev/tcp/", risk: 100, desc: "Bash reverse shell via /dev/tcp" },
  { name: "python_revshell", pattern: "python[23]?\\s+-c\\s*['\"].*(?:socket|subprocess|pty\\.spawn)", risk: 100, desc: "Python reverse shell" },
  { name: "perl_revshell",   pattern: "perl\\s+-e\\s*['\"].*(?:socket|exec|fork)", risk: 95, desc: "Perl reverse shell" },
  { name: "php_revshell",    pattern: "php\\s+-r\\s*['\"].*(?:fsockopen|exec|shell_exec|system)", risk: 95, desc: "PHP reverse shell" },
  // Malware / persistence
  { name: "crypto_miner",    pattern: "\\b(?:xmrig|minerd|cgminer|bfgminer|cpuminer|stratum\\+tcp)\\b", risk: 90, desc: "Cryptocurrency miner" },
  { name: "cron_persist",    pattern: "\\b(?:crontab\\s+-e|echo\\b.*>.*crontab|/etc/cron)", risk: 70, desc: "Cron persistence mechanism" },
  { name: "ssh_key_inject",  pattern: ">>?\\s*~?/?\\.ssh/authorized_keys", risk: 85, desc: "SSH key injection" },
  { name: "fork_bomb",       pattern: ":\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\}\\s*;", risk: 100, desc: "Fork bomb" },
  // System sabotage
  { name: "iptables_flush",  pattern: "\\biptables\\b.*-F|\\biptables\\b.*--flush|\\bufw\\s+disable\\b", risk: 80, desc: "Flushing firewall rules" },
  { name: "kill_all",        pattern: "\\bkillall\\b|\\bkill\\s+-9\\s+-1\\b|\\bpkill\\s+-9\\b", risk: 75, desc: "Mass process killing" },
  { name: "svc_disable",     pattern: "\\bsystemctl\\b.*(?:disable|stop|mask).*(?:firewall|ufw|iptables|sshd|fail2ban)", risk: 85, desc: "Disabling security services" },
  // Windows-specific
  { name: "win_format",      pattern: "\\bformat\\b.*[A-Z]:\\s*/[yY]|\\bdiskpart\\b", risk: 95, desc: "Windows disk format/diskpart" },
  { name: "win_reg_delete",  pattern: "\\breg\\b.*(?:delete|add).*(?:HKLM|HKCU|HKCR).*/f", risk: 85, desc: "Windows registry deletion" },
  { name: "ps_download_exec", pattern: "(?:powershell|pwsh).*(?:IEX|Invoke-Expression|DownloadString|DownloadFile).*http", risk: 90, desc: "PowerShell download-and-execute" },
  { name: "win_del_recurse", pattern: "\\bdel\\b.*/[sS].*/[fFqQ]|\\brmdir\\b.*/[sS].*/[qQ]", risk: 90, desc: "Windows recursive force delete" },
];

export class ShellGuard extends BaseGuard {
  private compiled: Array<{ name: string; risk: number; desc: string; re: RegExp }>;

  constructor(mode = "enforce", customRules?: GuardRule[]) {
    super("shell", mode);
    this.compiled = [];
    for (const rule of [...SHELL_RULES, ...(customRules ?? [])]) {
      try {
        this.compiled.push({ name: rule.name, risk: rule.risk, desc: rule.desc, re: new RegExp(rule.pattern, "i") });
      } catch { /* skip invalid regex */ }
    }
  }

  protected analyze(action: string, _context: Record<string, unknown>): GuardResult {
    const cmd = action.trim();
    const matched: string[] = [];
    let maxRisk = 0;

    for (const rule of this.compiled) {
      if (rule.re.test(cmd)) {
        matched.push(rule.name);
        maxRisk = Math.max(maxRisk, rule.risk);
      }
    }

    const decision = maxRisk >= 80 ? GuardDecision.BLOCK : maxRisk >= 40 ? GuardDecision.WARN : GuardDecision.ALLOW;

    return BaseGuard.buildResult(
      decision, this.guardType, action,
      matched.length > 0 ? `Matched ${matched.length} rule(s): ${matched.join(", ")}` : "No dangerous patterns detected",
      maxRisk, matched,
    );
  }
}
