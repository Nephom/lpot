package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func dashboardLogPath(name string) string {
	switch name {
	case "result":
		return RESULT_FILE
	case "summary":
		return REBOOT_LOG
	case "lspci":
		return LPOTSCAN_LOG
	case "config_space":
		return CONFIG_CHANGES_LOG
	default:
		return ""
	}
}

func startDashboard() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	})
	mux.HandleFunc("/api/result", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		data, err := os.ReadFile(RESULT_FILE)
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"status":"EMPTY","message":"No LPOT result is available. Run a normal test with -t first."}`)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		path := dashboardLogPath(r.URL.Query().Get("name"))
		if path == "" {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if r.URL.Query().Get("name") == "result" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Write(data)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		path, err := configDumpPath(r.URL.Query().Get("bdf"))
		if err != nil {
			http.Error(w, "invalid BDF", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start dashboard listener: %w", err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	url := "http://" + listener.Addr().String()
	fmt.Printf("LPOT dashboard listening at %s\n", url)
	go openDashboardBrowser(url)
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(listener) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("dashboard server stopped: %w", err)
	}
}

func openDashboardBrowser(url string) {
	candidates := []string{"/usr/bin/firefox", "/usr/bin/firefox-esr"}
	for _, name := range []string{"firefox", "firefox-esr"} {
		if path, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, path)
		}
	}
	for _, path := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, path, url).Run()
		cancel()
		if err == nil {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Suggestion: open the dashboard URL manually in Firefox: %s\n", url)
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LPOT Test Dashboard</title>
<style>
:root { color-scheme: dark; --bg:#10151d; --panel:#18212d; --line:#2b3a4d; --text:#e7edf5; --muted:#9eacbd; --green:#43d17c; --red:#ff6b6b; --yellow:#f4c95d; --blue:#6eb6ff; }
* { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
main { max-width:1280px; margin:0 auto; padding:28px 20px 60px; } h1,h2 { margin:0; } h1 { font-size:28px; letter-spacing:.02em; } h2 { font-size:16px; margin-bottom:14px; }
.sub { color:var(--muted); margin:4px 0 24px; } .hero,.panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px; }
.hero { display:flex; align-items:center; justify-content:space-between; gap:20px; margin-bottom:18px; } .status { font-size:30px; font-weight:800; letter-spacing:.06em; }
 .PASS,.KEEP { color:var(--green); } .FAIL,.UNVERIFIED { color:var(--red); } .INFO,.NOTICE,.RUNNING { color:var(--yellow); } .INCOMPLETE,.SKIP { color:var(--blue); }
.reason { color:var(--muted); text-align:right; max-width:560px; } .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:18px; }
.metric { background:#121a24; border:1px solid var(--line); border-radius:10px; padding:14px; } .metric b { display:block; font-size:22px; } .metric span { color:var(--muted); }
.columns { display:grid; grid-template-columns:1fr 1.35fr; gap:18px; margin-bottom:18px; } .check { display:flex; justify-content:space-between; border-bottom:1px solid var(--line); padding:10px 0; } .check:last-child { border:0; }
 .table-wrap { overflow:auto; } table { border-collapse:collapse; width:100%; min-width:680px; } th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; } th { color:var(--muted); font-weight:600; }
 select { background:#121a24; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:7px 10px; margin-bottom:10px; } .empty { color:var(--muted); padding:12px 0; }
 .help-button { float:right; width:28px; height:28px; border:1px solid var(--blue); border-radius:50%; background:transparent; color:var(--blue); font-weight:800; cursor:pointer; }
 .help-backdrop { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; padding:20px; background:rgba(0,0,0,.7); z-index:10; }
 .help-backdrop[hidden] { display:none; }
 .help-dialog { max-width:680px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:22px; box-shadow:0 18px 60px rgba(0,0,0,.45); }
 .help-dialog h2 { margin-bottom:12px; } .help-dialog p { color:var(--muted); } .help-dialog code { color:var(--text); }
 .help-close { float:right; border:0; background:transparent; color:var(--muted); font-size:20px; cursor:pointer; }
 .config-button { display:inline-block; padding:4px 8px; border:1px solid var(--blue); border-radius:5px; color:var(--blue); text-decoration:none; white-space:nowrap; }
 .config-button.disabled { border-color:var(--line); color:var(--muted); opacity:.55; cursor:not-allowed; }
a { color:var(--blue); } code { color:#cbd8e8; } @media (max-width:800px) { .hero { display:block; } .reason { text-align:left; margin-top:10px; } .grid { grid-template-columns:repeat(2,1fr); } .columns { grid-template-columns:1fr; } }
</style></head>
<body><main>
<div class="hero"><div><h1>LPOT PCIe Stability Test</h1><div class="sub" id="run">Loading result...</div></div><div class="status" id="status">...</div><div class="reason" id="reason"></div></div>
<div class="grid" id="metrics"></div>
<div class="columns"><section class="panel"><h2>Checks</h2><div id="checks"></div></section><section class="panel"><h2>Run Information</h2><div id="info"></div></section></div>
<section class="panel" style="margin-bottom:18px"><h2>PCIe Link Evidence <button class="help-button" id="linkHelp" title="Explain PCIe link fields">?</button></h2><div class="sub">Source: sysfs raw PCI configuration space. lspci capability comparison is shown separately in Checks.</div><div class="table-wrap" id="classificationDevices"></div></section>
 <section class="panel" style="margin-bottom:18px"><h2>Problems and Events</h2><select id="severity"><option value="ALL">All severities</option><option value="FAIL">FAIL only</option><option value="NOTICE">NOTICE only</option><option value="INFO">INFO only</option></select><div class="table-wrap" id="problems"></div></section>
<section class="panel" style="margin-bottom:18px"><h2>Artifacts</h2><div id="artifacts"></div></section>
<section class="panel"><h2>Cycle Timeline</h2><div class="table-wrap" id="cycles"></div></section>
<div class="help-backdrop" id="linkHelpDialog" hidden><div class="help-dialog" role="dialog" aria-modal="true" aria-labelledby="linkHelpTitle"><button type="button" class="help-close" id="linkHelpClose" aria-label="Close" onclick="document.getElementById('linkHelpDialog').hidden=true; return false;">x</button><h2 id="linkHelpTitle">PCIe Link Field Guide</h2><p><b>PCIe Cap</b> means the PCI Express capability was found in the raw PCI configuration space. The value is the capability offset, not a speed or bandwidth.</p><p><b>LnkCap (Max)</b> is the link capability advertised by the device: the maximum supported link speed and width, such as <code>16GT/s x16</code>.</p><p><b>LnkSta (Current)</b> is the currently negotiated link speed and width, such as <code>8GT/s x8</code>. <code>NO LINK</code> means no active width or speed was reported. An invalid width code is not treated as a usable link.</p><p>The table values come from sysfs raw PCI configuration bytes. The lspci check separately compares the selected <code>Dev*</code> and <code>Lnk*</code> capability fields.</p></div></div>
</main><script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge = s => '<b class="'+esc(s)+'">'+esc(s)+'</b>';
function render(d) {
  const status = document.getElementById('status'); status.className='status '+esc(d.status); status.textContent=d.status;
  document.getElementById('reason').textContent=d.message||'';
  document.getElementById('run').textContent='Run '+(d.run_id||'unknown')+' | Updated '+(d.updated_at||'unknown');
  document.getElementById('metrics').innerHTML=[['Total cycles',d.total_cycles],['Completed',d.completed_cycles],['Successful',d.successful_cycles],['Failed',d.failed_cycles]].map(x=>'<div class="metric"><b>'+esc(x[1])+'</b><span>'+x[0]+'</span></div>').join('');
  const checks=[['Topology',d.checks?.topology],['lspci',d.checks?.lspci],['Config space',d.checks?.config_space],['Config noise',d.checks?.config_noise]];
  document.getElementById('checks').innerHTML=checks.map(x=>'<div class="check"><span>'+x[0]+'<small style="display:block;color:var(--muted)">'+esc(x[1]?.message||'')+'</small></span>'+badge(x[1]?.status||'UNKNOWN')+'</div>').join('');
  document.getElementById('info').innerHTML='<div class="check"><span>Started</span><code>'+esc(d.started_at||'-')+'</code></div><div class="check"><span>Finished</span><code>'+esc(d.finished_at||'-')+'</code></div><div class="check"><span>Checkpoint</span><code>'+esc(d.checkpoint)+'</code></div>';
  const cl=d.classification||{};
  const devices=cl.devices||[]; document.getElementById('classificationDevices').innerHTML=devices.length?'<table><thead><tr><th>BDF</th><th>Decision</th><th>PCIe Cap</th><th>Raw LnkCap</th><th>Raw LnkSta</th><th>lspci LnkCap</th><th>lspci LnkSta</th><th>Config Space</th><th>Reason</th></tr></thead><tbody>'+devices.map(x=>{const keep=x.decision==='KEEP'; const view=keep?'<a class="config-button" href="/api/config?bdf='+encodeURIComponent(x.bdf)+'" target="_blank" rel="noopener">View</a>':'<span class="config-button disabled" aria-disabled="true">View</span>'; return '<tr><td><code>'+esc(x.bdf)+'</code></td><td>'+badge(x.decision||'UNKNOWN')+'</td><td>'+esc(x.pcie_capability||'-')+'</td><td>'+esc(x.link_capability||'-')+'</td><td>'+esc(x.link_status||'-')+'</td><td>'+esc(x.lspci_link_capability||'-')+'</td><td>'+esc(x.lspci_link_status||'-')+'</td><td>'+view+'</td><td>'+esc(x.reason||x.verification||'-')+'</td></tr>'}).join('')+'</tbody></table>':'<div class="empty">No classification data.</div>';
  const filter=document.getElementById('severity').value; const problems=(d.problems||[]).filter(p=>filter==='ALL'||p.severity===filter);
  document.getElementById('problems').innerHTML=problems.length?'<table><thead><tr><th>Severity</th><th>Category</th><th>Cycle</th><th>Device</th><th>Message</th><th>Log</th></tr></thead><tbody>'+problems.map(p=>'<tr><td>'+badge(p.severity)+'</td><td>'+esc(p.category)+'</td><td>'+esc(p.cycle)+'</td><td>'+esc(p.bdf||'-')+'</td><td>'+esc(p.message)+'</td><td><code>'+esc(p.details_log||'-')+'</code></td></tr>').join('')+'</tbody></table>':'<div class="empty">No matching problems.</div>';
  document.getElementById('artifacts').innerHTML=Object.entries(d.artifacts||{}).map(([name,path])=>'<div class="check"><span>'+esc(name)+'</span><a href="/api/log?name='+encodeURIComponent(name)+'" target="_blank">'+esc(path)+'</a></div>').join('')||'<div class="empty">No artifacts.</div>';
  const cycles=d.cycles||[]; document.getElementById('cycles').innerHTML=cycles.length?'<table><thead><tr><th>Cycle</th><th>Status</th><th>Topology</th><th>lspci</th><th>Config</th><th>Events</th></tr></thead><tbody>'+cycles.slice().reverse().map(c=>'<tr><td>'+String(c.number).padStart(3,'0')+'</td><td>'+badge(c.status)+'</td><td>'+badge(c.topology)+'</td><td>'+badge(c.lspci)+'</td><td>'+badge(c.config_space)+'</td><td>'+esc((c.events||[]).length)+'</td></tr>').join('')+'</tbody></table>':'<div class="empty">No completed cycles.</div>';
}
document.getElementById('severity').addEventListener('change',()=>window.current&&render(window.current));
const linkHelp=document.getElementById('linkHelpDialog'); document.getElementById('linkHelp').addEventListener('click',()=>linkHelp.hidden=false); document.getElementById('linkHelpClose').addEventListener('click',()=>linkHelp.hidden=true); linkHelp.addEventListener('click',e=>{if(e.target===linkHelp)linkHelp.hidden=true}); document.addEventListener('keydown',e=>{if(e.key==='Escape')linkHelp.hidden=true});
fetch('/api/result',{cache:'no-store'}).then(r=>r.json()).then(d=>{window.current=d;render(d)}).catch(e=>{document.getElementById('reason').textContent='Unable to load /lpot/result.json: '+e});
</script></body></html>`
