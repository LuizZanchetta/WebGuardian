// WebGuardian — app de painel (Windows, .NET Framework 4.8, C# 5)
// Versão oficial. Fonte oficial: https://github.com/LuizZanchetta/WebGuardian
// Assinatura digital oficial: WG-D0C5-ACA9-5777-6D53-ED11 (confira com VERIFICAR AUTENTICIDADE.bat)
// Compilar: app\compilar.ps1  ->  ..\WebGuardian.exe
//
// Como funciona:
//  1. Este app roda como usuário comum (nunca como Administrador).
//  2. Ele pede ao monitor do WebGuardian (que roda como Administrador) um link de entrada,
//     criando o arquivo-gatilho %LOCALAPPDATA%\Guardiao\abrir-app.
//  3. O monitor responde em %LOCALAPPDATA%\Guardiao\app.url com um código de USO ÚNICO
//     válido por 60 s (a chave do painel nunca é gravada em disco nem no histórico).
//  4. O app abre esse link numa janela própria (motor do Microsoft Edge em modo app,
//     sem barra de endereço), com perfil separado em %LOCALAPPDATA%\Guardiao\perfil-app.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("WebGuardian")]
[assembly: AssemblyDescription("WebGuardian - painel de proteção contra acesso indevido")]
[assembly: AssemblyProduct("WebGuardian")]
[assembly: AssemblyCompany("Uso pessoal")]
[assembly: AssemblyCopyright("Uso pessoal - não distribuído")]
[assembly: AssemblyVersion("1.7.0.0")]
[assembly: AssemblyFileVersion("1.7.0.0")]

namespace WebGuardian
{
    static class App
    {
        const string NomeTarefa = "Guardiao - Monitor de Acesso";
        static readonly string Pasta = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Guardiao");
        static readonly Regex UrlValida = new Regex(@"^http://127\.0\.0\.1:\d{2,5}/entrar\?c=[0-9a-f]{32,64}$");

        [STAThread]
        static int Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            bool primeiro;
            using (var trava = new Mutex(true, @"Local\GuardiaoApp", out primeiro))
            {
                if (!primeiro) return 0;   // outro clique já está abrindo
                try { return Abrir(); }
                catch (Exception ex)
                {
                    MessageBox.Show("Não foi possível abrir o WebGuardian.\n\n" + ex.Message, "WebGuardian",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return 1;
                }
            }
        }

        static int Abrir()
        {
            Directory.CreateDirectory(Pasta);
            string gatilho = Path.Combine(Pasta, "abrir-app");
            string resposta = Path.Combine(Pasta, "app.url");
            Apagar(resposta);

            // Monitor parado? Oferece iniciar (pede Administrador uma vez)
            if (!MonitorRodando())
            {
                var r = MessageBox.Show(
                    "O monitor do WebGuardian não está rodando, então seu PC não está sendo vigiado.\n\n" +
                    "Deseja iniciá-lo agora? O Windows vai pedir permissão de Administrador.",
                    "WebGuardian", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r != DialogResult.Yes) return 2;
                if (!IniciarMonitor()) return 2;
            }

            File.WriteAllText(gatilho, "");
            Splash splash = null;
            var relogio = Stopwatch.StartNew();
            try
            {
                // O monitor atende em menos de 1 s; logo após ligar o PC pode levar ~30 s
                while (relogio.Elapsed.TotalSeconds < 90)
                {
                    string url = LerResposta(resposta);
                    if (url != null) { AbrirJanela(url); return 0; }
                    if (splash == null && relogio.ElapsedMilliseconds > 700)
                    {
                        splash = new Splash();
                        splash.Show();
                    }
                    if (splash != null)
                    {
                        if (relogio.Elapsed.TotalSeconds > 8) splash.Texto("O WebGuardian está terminando de iniciar…");
                        Application.DoEvents();
                    }
                    Thread.Sleep(100);
                }
            }
            finally
            {
                if (splash != null) splash.Close();
                Apagar(gatilho);
            }
            MessageBox.Show("O monitor do WebGuardian não respondeu.\n\nReinicie o computador ou rode o INSTALAR WEBGUARDIAN.bat de novo.",
                "WebGuardian", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return 3;
        }

        static string LerResposta(string arquivo)
        {
            if (!File.Exists(arquivo)) return null;
            try
            {
                string url = File.ReadAllText(arquivo).Trim();
                Apagar(arquivo);
                // Só aceita um link do próprio PC no formato esperado (evita redirecionamento malicioso)
                return UrlValida.IsMatch(url) ? url : null;
            }
            catch (IOException) { return null; }   // monitor ainda escrevendo: tenta de novo
        }

        static void AbrirJanela(string url)
        {
            string edge = AcharEdge();
            if (edge == null) { Process.Start(url); return; }   // sem Edge: navegador padrão
            string perfil = Path.Combine(Pasta, "perfil-app");
            var psi = new ProcessStartInfo(edge, string.Format(
                "--app=\"{0}\" --user-data-dir=\"{1}\" --window-size=1360,900 --no-first-run --no-default-browser-check " +
                "--disable-sync --disable-features=msEdgeSidebarV2,msHubApps,EdgeCollections",
                url, perfil));
            psi.UseShellExecute = false;
            Process.Start(psi);
        }

        static string AcharEdge()
        {
            foreach (var raiz in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                using (var k = raiz.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"))
                {
                    var v = k == null ? null : k.GetValue("") as string;
                    if (!string.IsNullOrEmpty(v) && File.Exists(v)) return v;
                }
            }
            foreach (var pf in new[] { Environment.GetEnvironmentVariable("ProgramFiles(x86)"), Environment.GetEnvironmentVariable("ProgramFiles") })
            {
                if (pf == null) continue;
                string c = Path.Combine(pf, @"Microsoft\Edge\Application\msedge.exe");
                if (File.Exists(c)) return c;
            }
            return null;
        }

        static bool MonitorRodando()
        {
            // Lê o estado da tarefa agendada (não precisa de Administrador)
            try
            {
                var psi = new ProcessStartInfo("schtasks.exe", "/Query /TN \"" + NomeTarefa + "\" /FO CSV /NH");
                psi.UseShellExecute = false; psi.CreateNoWindow = true; psi.RedirectStandardOutput = true;
                using (var p = Process.Start(psi))
                {
                    string saida = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    if (p.ExitCode != 0) return true;   // não deu para consultar: tenta abrir mesmo assim
                    // "Em execução" (pt-BR) ou "Running" (en)
                    return saida.IndexOf("execu", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           saida.IndexOf("Running", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch { return true; }
        }

        static bool IniciarMonitor()
        {
            try
            {
                var psi = new ProcessStartInfo("powershell.exe",
                    "-NoProfile -WindowStyle Hidden -Command \"Start-ScheduledTask -TaskName '" + NomeTarefa + "'\"");
                psi.Verb = "runas"; psi.UseShellExecute = true; psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (var p = Process.Start(psi)) { p.WaitForExit(15000); }
                return true;
            }
            catch (Win32Exception) { return false; }   // permissão negada no aviso do Windows
        }

        static void Apagar(string arquivo)
        {
            try { if (File.Exists(arquivo)) File.Delete(arquivo); } catch { }
        }
    }

    // Janelinha "Abrindo o WebGuardian…" (só aparece se demorar)
    class Splash : Form
    {
        readonly Label rotulo;
        public Splash()
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            ShowInTaskbar = true;
            Text = "WebGuardian";
            BackColor = Color.FromArgb(15, 16, 18);
            Size = new Size(380, 112);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var img = new PictureBox();
            img.Size = new Size(40, 40); img.Location = new Point(24, 36); img.SizeMode = PictureBoxSizeMode.Zoom;
            try { img.Image = Icon.ExtractAssociatedIcon(Application.ExecutablePath).ToBitmap(); } catch { }
            Controls.Add(img);

            var titulo = new Label();
            titulo.Text = "WebGuardian"; titulo.ForeColor = Color.FromArgb(247, 248, 248);
            titulo.Font = new Font("Segoe UI Semibold", 12f); titulo.AutoSize = true; titulo.Location = new Point(80, 30);
            Controls.Add(titulo);

            rotulo = new Label();
            rotulo.Text = "Abrindo o painel…"; rotulo.ForeColor = Color.FromArgb(138, 143, 152);
            rotulo.Font = new Font("Segoe UI", 9.5f); rotulo.AutoSize = true; rotulo.Location = new Point(81, 58);
            Controls.Add(rotulo);
        }
        public void Texto(string t) { if (rotulo.Text != t) rotulo.Text = t; }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using (var p = new Pen(Color.FromArgb(44, 46, 51))) e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
        }
    }
}
