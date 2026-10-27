using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;

namespace IpGuard {
    public sealed class Settings {
        public string expectedIp = "";
        public int intervalSeconds = 2;
    }
    public sealed class Rule {
        public Settings settings = new Settings();
        public bool rulesLocked, enabled;
        public bool stopOnProbeFailure=true;
    }
    public sealed class Target {
        public string service;
        public string id;
        public string name;
        public string path;
        public string arguments = "";
        public bool enabled;
    }
    public sealed class Config {
        public int format = 2;
        public Dictionary<string,Rule> services = new Dictionary<string,Rule> { { "claude",new Rule() }, { "chatgpt",new Rule() } };
        public List<Target> apps = new List<Target>();
        public bool autostart;
        public string networkAdapterId="", networkAdapterName="";
    }
    public static class Data {
        public static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IPGuard");
        public static readonly string ConfigPath = Path.Combine(DirectoryPath, "settings.json");
        public static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = 1048576 }; }
        public static Config Load() {
            if (!File.Exists(ConfigPath)) return new Config();
            string source = File.ReadAllText(ConfigPath);
            bool migrate;
            Config c=Parse(source,out migrate);
            if(migrate) {
                string backup=ConfigPath+".pre-independent";
                if(!File.Exists(backup)) File.Copy(ConfigPath,backup);
                Save(c);
            }
            return c;
        }
        public static Config Parse(string source,out bool migrate) {
            var fields=Json().Deserialize<Dictionary<string,object>>(source);
            if(fields==null) throw new Exception("配置文件损坏，请恢复备份。");
            migrate=!fields.ContainsKey("format");
            Config c=migrate ? MigrateLegacy(source,fields) : Json().Deserialize<Config>(source);
            if(c==null || c.format!=2 || c.services==null || c.services.Count!=2 || !c.services.ContainsKey("claude") || !c.services.ContainsKey("chatgpt") || c.apps==null) throw new Exception("独立防护配置无效，请恢复备份。");
            foreach(Rule rule in c.services.Values) {
                if(rule==null || rule.settings==null) throw new Exception("服务规则配置无效。");
                if(rule.rulesLocked || rule.settings.expectedIp!="") Validate(rule.settings);
                if(rule.settings.intervalSeconds<1 || rule.settings.intervalSeconds>60) throw new Exception("检测间隔应为 1–60 秒。");
                if(rule.enabled && !rule.rulesLocked) throw new Exception("未锁定的服务不能启用。");
            }
            foreach(Target t in c.apps) Validate(t,false);
            if(c.apps.Select(t=>t.id).Distinct().Count()!=c.apps.Count || c.apps.Select(t=>t.path.ToLowerInvariant()).Distinct().Count()!=c.apps.Count) throw new Exception("配置中有重复程序。");
            return c;
        }
        // 0.9/0.10 deployments persist one shared rule. Remove this reader when those backups no longer need importing.
        sealed class LegacySettings { public string service="claude"; public string expectedIp=""; public int intervalSeconds=2; }
        sealed class LegacyConfig {
            public LegacySettings settings=null; public List<Target> apps=null;
            public bool autostart=false,rulesLocked=false; public string ipSource="claude-ai";
            public string networkAdapterId="",networkAdapterName="";
        }
        static Config MigrateLegacy(string source,Dictionary<string,object> fields) {
            LegacyConfig old=Json().Deserialize<LegacyConfig>(source);
            if(old==null || old.settings==null || old.apps==null || old.ipSource!="claude-ai") throw new Exception("旧配置无效，请恢复备份。");
            string selected=old.settings.service;
            if(selected!="both") ValidateService(selected);
            bool locked=fields.ContainsKey("rulesLocked") ? old.rulesLocked : old.settings.expectedIp!="";
            Settings settings=new Settings { expectedIp=old.settings.expectedIp,intervalSeconds=old.settings.intervalSeconds };
            if(locked || settings.expectedIp!="") Validate(settings);
            Config c=new Config { apps=old.apps,autostart=old.autostart,networkAdapterId=old.networkAdapterId,networkAdapterName=old.networkAdapterName };
            foreach(string key in new[] { "claude","chatgpt" }) if(selected==key || selected=="both")
                c.services[key]=new Rule { settings=new Settings { expectedIp=settings.expectedIp,intervalSeconds=settings.intervalSeconds },rulesLocked=locked,enabled=locked };
            foreach(Target t in c.apps) {
                string name=Path.GetFileName(t.path ?? "");
                t.service=String.Equals(name,"ChatGPT.exe",StringComparison.OrdinalIgnoreCase) ? "chatgpt" : String.Equals(name,"Claude.exe",StringComparison.OrdinalIgnoreCase) ? "claude" : selected=="chatgpt" ? "chatgpt" : "claude";
            }
            return c;
        }

        public static void Save(Config c) {
            Directory.CreateDirectory(DirectoryPath);
            string temp = ConfigPath + ".tmp";
            File.WriteAllText(temp, Json().Serialize(c), new UTF8Encoding(false));
            if (File.Exists(ConfigPath)) File.Replace(temp, ConfigPath, ConfigPath + ".bak");
            else File.Move(temp, ConfigPath);
        }
        public static bool PublicV4(string value) {
            IPAddress ip;
            if (!IPAddress.TryParse(value, out ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != value) return false;
            byte[] b = ip.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 ||
                (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254) ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && (b[1] == 168 || (b[1] == 0 && (b[2] == 0 || b[2] == 2)))) ||
                (b[0] == 198 && (b[1] == 18 || b[1] == 19 || (b[1] == 51 && b[2] == 100))) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113));
        }
        public static void Validate(Settings s) {
            if (s == null) throw new Exception("请输入有效的防护规则。");
            if (!PublicV4(s.expectedIp)) throw new Exception("请输入有效的公网 IPv4 地址。");
            if (s.intervalSeconds < 1 || s.intervalSeconds > 60) throw new Exception("检测间隔应为 1–60 秒。");
        }
        public static void ValidateService(string service) {
            if(service!="claude" && service!="chatgpt") throw new Exception("请选择 Claude 或 ChatGPT。");
        }
        public static void Validate(Target t, bool exists) {
            ValidateService(t==null ? null : t.service);
            Guid id;
            if (t == null || !Guid.TryParseExact(t.id, "D", out id)) throw new Exception("程序标识无效。");
            if (String.IsNullOrWhiteSpace(t.name) || t.name.Length > 100) throw new Exception("请输入程序名称。");
            if (String.IsNullOrWhiteSpace(t.path) || t.path.Length > 1024 || !Path.IsPathRooted(t.path) || t.path.IndexOf('"') >= 0 || Path.GetExtension(t.path).ToLowerInvariant() != ".exe") throw new Exception("请选择 EXE 的完整路径。");
            t.path = Path.GetFullPath(t.path);
            if (t.path.StartsWith(@"\\") || (exists && !File.Exists(t.path))) throw new Exception("请选择本机存在的 EXE 文件。");
            if (t.arguments == null || t.arguments.Length > 4096 || t.arguments.IndexOf('\0') >= 0) throw new Exception("启动参数无效。");
            string name = Path.GetFileName(t.path).ToLowerInvariant();
            if(name=="ipguard.terminal.exe") throw new Exception("启动门卫保留原启动方式。");
            string[] critical = { "ipguard.native.exe", "ip guard.exe", "explorer.exe", "winlogon.exe", "csrss.exe", "services.exe", "lsass.exe", "svchost.exe", "smss.exe", "wininit.exe", "dwm.exe", "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "reg.exe", "netsh.exe", "schtasks.exe", "rundll32.exe" };
            if (critical.Contains(name)) throw new Exception("请选择普通应用；系统与恢复工具保留原有启动方式。");
        }
        public static string Quote(string value) {
            StringBuilder b = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') b.Append('\\', slashes * 2 + 1); else b.Append('\\', slashes);
                b.Append(c); slashes = 0;
            }
            b.Append('\\', slashes * 2); return b.Append('"').ToString();
        }
    }
}
