# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Generador de Reporte HTML Profesional
Analyst : Apo1o13
Build   : 2026-04-30

Genera un reporte HTML autocontenido con mapa SVG, tablas de hallazgos,
credenciales, evidencias y recomendaciones.
"""

import datetime
import os
import sys
import re


def _p(msg):
    print(msg); sys.stdout.flush()


def generar_reporte(datos, nombre_archivo=None):
    """
    datos = {
        'analyst':       str,
        'version':       str,
        'fecha_inicio':  str,
        'fecha_fin':     str,
        'hosts_escaneados': [str],
        'vulnerabilidades': [{host, vector, estado}],
        'credenciales':  [{host, user, password, method, time}],
        'evidencias':    [{tipo, host, detalle, output}],
        'hosts_comprometidos': [{host, metodo, usuario, password}],
        'red_interna':   [{ip, port, service}],
    }
    """
    if not nombre_archivo:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = "panter_jboss_reporte_%s.html" % ts

    analyst  = datos.get('analyst', 'Apo1o13')
    version  = datos.get('version', '1.3.0')
    f_inicio = datos.get('fecha_inicio', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    f_fin    = datos.get('fecha_fin',    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    vulns       = datos.get('vulnerabilidades', [])
    creds       = datos.get('credenciales', [])
    evidencias  = datos.get('evidencias', [])
    comprometidos = datos.get('hosts_comprometidos', [])
    red_interna = datos.get('red_interna', [])
    hosts_scan  = datos.get('hosts_escaneados', [])

    # ── SVG Network Map ──────────────────────────────────────────────
    svg = _generar_svg(comprometidos, red_interna)

    # ── Tablas HTML ───────────────────────────────────────────────────
    tabla_vulns  = _tabla_html(
        ["Host", "Vector", "Estado"],
        [[v.get('host',''), v.get('vector',''), v.get('estado','')] for v in vulns],
        clase="table-vuln"
    )
    tabla_creds  = _tabla_html(
        ["Host", "Usuario", "Password", "Metodo", "Hora"],
        [[c.get('host',''), c.get('user',''), c.get('password',''),
          c.get('method',''), c.get('time','')] for c in creds],
        clase="table-cred"
    )
    tabla_comp   = _tabla_html(
        ["Host Comprometido", "Vector", "Usuario", "Password"],
        [[h.get('host',''), h.get('metodo',''), h.get('usuario',''), h.get('password','')]
         for h in comprometidos],
        clase="table-comp"
    )
    tabla_red    = _tabla_html(
        ["IP", "Puerto", "Servicio"],
        [[r.get('ip',''), str(r.get('port','')), r.get('service','')] for r in red_interna],
        clase="table-net"
    )

    # ── Evidencias (collapsible) ───────────────────────────────────────
    ev_html = ""
    for i, ev in enumerate(evidencias):
        output_escaped = ev.get('output','').replace('<','&lt;').replace('>','&gt;')
        ev_html += """
        <div class="evidence-block">
            <div class="evidence-header" onclick="toggle('ev%d')">
                <span class="ev-tipo">%s</span>
                <span class="ev-host">%s</span>
                <span class="ev-det">%s</span>
                <span class="ev-toggle">▼</span>
            </div>
            <div class="evidence-body" id="ev%d">
                <pre>%s</pre>
            </div>
        </div>
        """ % (i, ev.get('tipo',''), ev.get('host',''), ev.get('detalle',''),
               i, output_escaped)

    # ── Resumen ejecutivo ─────────────────────────────────────────────
    nivel_riesgo = "CRITICO" if comprometidos else ("ALTO" if vulns else "MEDIO")
    color_riesgo = "#e74c3c" if nivel_riesgo == "CRITICO" else "#e67e22"

    html = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PANTER JBOSS — Reporte de Pentest</title>
<style>
  :root {
    --bg:      #0d1117;
    --bg2:     #161b22;
    --bg3:     #21262d;
    --border:  #30363d;
    --red:     #f85149;
    --green:   #3fb950;
    --yellow:  #d29922;
    --blue:    #58a6ff;
    --cyan:    #39d353;
    --white:   #c9d1d9;
    --muted:   #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--white); font-family: 'Courier New', monospace; }

  /* Header */
  .header { background: linear-gradient(135deg, #1a0000, #0d1117);
            border-bottom: 2px solid var(--red); padding: 30px 40px; }
  .header-title { font-size: 2em; color: var(--red); font-weight: bold; letter-spacing: 4px; }
  .header-sub   { color: var(--muted); margin-top: 6px; font-size: 0.9em; }
  .header-meta  { display: flex; gap: 30px; margin-top: 20px; flex-wrap: wrap; }
  .meta-item    { background: var(--bg3); border: 1px solid var(--border);
                  padding: 10px 18px; border-radius: 6px; }
  .meta-label   { color: var(--muted); font-size: 0.75em; text-transform: uppercase; }
  .meta-value   { color: var(--white); font-size: 1em; margin-top: 2px; }

  /* Risk badge */
  .risk-badge { display: inline-block; padding: 4px 14px; border-radius: 20px;
                font-weight: bold; font-size: 0.85em; color: #fff;
                background: %s; margin-top: 6px; }

  /* Nav */
  .nav { background: var(--bg2); border-bottom: 1px solid var(--border);
         padding: 0 40px; display: flex; gap: 0; overflow-x: auto; }
  .nav a { color: var(--muted); text-decoration: none; padding: 14px 20px;
           display: block; font-size: 0.9em; border-bottom: 2px solid transparent; }
  .nav a:hover { color: var(--white); border-bottom-color: var(--red); }

  /* Main */
  main { max-width: 1300px; margin: 0 auto; padding: 30px 40px; }
  .section { margin-bottom: 40px; }
  .section-title { color: var(--red); font-size: 1.1em; font-weight: bold;
                   text-transform: uppercase; letter-spacing: 2px;
                   border-bottom: 1px solid var(--border); padding-bottom: 10px;
                   margin-bottom: 20px; }

  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
           gap: 16px; margin-bottom: 30px; }
  .card  { background: var(--bg2); border: 1px solid var(--border);
           border-radius: 8px; padding: 20px; text-align: center; }
  .card-num   { font-size: 2.4em; font-weight: bold; }
  .card-label { color: var(--muted); font-size: 0.8em; text-transform: uppercase;
                margin-top: 4px; }
  .card.red    { border-color: var(--red);    }
  .card.red    .card-num { color: var(--red);    }
  .card.green  { border-color: var(--green);  }
  .card.green  .card-num { color: var(--green);  }
  .card.yellow { border-color: var(--yellow); }
  .card.yellow .card-num { color: var(--yellow); }
  .card.blue   { border-color: var(--blue);   }
  .card.blue   .card-num { color: var(--blue);   }

  /* Tables */
  table { width: 100%%; border-collapse: collapse; font-size: 0.88em; }
  th { background: var(--bg3); color: var(--muted); text-transform: uppercase;
       font-size: 0.78em; letter-spacing: 1px; padding: 10px 14px;
       border-bottom: 1px solid var(--border); text-align: left; }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: var(--bg3); }
  .table-vuln td:last-child { color: var(--red); font-weight: bold; }
  .table-cred td:nth-child(3) { color: var(--yellow); font-weight: bold; }
  .table-comp { border: 1px solid var(--red); }
  .table-comp th { background: #1a0505; color: var(--red); }

  /* SVG map */
  .svg-container { background: var(--bg2); border: 1px solid var(--border);
                   border-radius: 8px; padding: 20px; overflow-x: auto; }
  svg text { font-family: 'Courier New', monospace; }

  /* Evidence */
  .evidence-block { border: 1px solid var(--border); border-radius: 6px;
                    margin-bottom: 10px; overflow: hidden; }
  .evidence-header { background: var(--bg3); padding: 12px 16px; cursor: pointer;
                     display: flex; gap: 16px; align-items: center; }
  .evidence-header:hover { background: var(--bg2); }
  .ev-tipo   { color: var(--red);   font-weight: bold; min-width: 140px; }
  .ev-host   { color: var(--blue);  min-width: 200px; }
  .ev-det    { color: var(--muted); flex: 1; }
  .ev-toggle { color: var(--muted); margin-left: auto; }
  .evidence-body { display: none; background: #0a0f14; padding: 16px; }
  .evidence-body pre { color: var(--green); font-size: 0.82em;
                       white-space: pre-wrap; word-break: break-all; }

  /* Remediation */
  .remed-block { background: var(--bg2); border-left: 3px solid var(--blue);
                 padding: 16px 20px; margin-bottom: 12px; border-radius: 0 6px 6px 0; }
  .remed-title { color: var(--blue); font-weight: bold; margin-bottom: 8px; }
  .remed-body  { color: var(--muted); font-size: 0.9em; line-height: 1.6; }

  /* Footer */
  .footer { text-align: center; padding: 30px; color: var(--muted);
            border-top: 1px solid var(--border); font-size: 0.82em; margin-top: 40px; }

  @media print {
    .nav, .evidence-header { cursor: default; }
    .evidence-body { display: block !important; }
    body { background: #fff; color: #000; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="header-title">◈ PANTER JBOSS — REPORTE DE PENTEST</div>
  <div class="header-sub">JBoss &amp; Java Deserialization Exploitation Framework v%s</div>
  <div class="risk-badge">NIVEL DE RIESGO: %s</div>
  <div class="header-meta">
    <div class="meta-item">
      <div class="meta-label">Analista</div>
      <div class="meta-value">%s</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Inicio</div>
      <div class="meta-value">%s</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Fin</div>
      <div class="meta-value">%s</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Hosts escaneados</div>
      <div class="meta-value">%d</div>
    </div>
  </div>
</div>

<nav class="nav">
  <a href="#resumen">Resumen</a>
  <a href="#mapa">Mapa de Red</a>
  <a href="#vulnerabilidades">Vulnerabilidades</a>
  <a href="#comprometidos">Comprometidos</a>
  <a href="#credenciales">Credenciales</a>
  <a href="#evidencias">Evidencias</a>
  <a href="#remediacion">Remediacion</a>
</nav>

<main>

  <!-- RESUMEN -->
  <section class="section" id="resumen">
    <div class="section-title">◈ Resumen Ejecutivo</div>
    <div class="cards">
      <div class="card red">
        <div class="card-num">%d</div>
        <div class="card-label">Hosts Comprometidos</div>
      </div>
      <div class="card red">
        <div class="card-num">%d</div>
        <div class="card-label">Vulnerabilidades</div>
      </div>
      <div class="card yellow">
        <div class="card-num">%d</div>
        <div class="card-label">Credenciales</div>
      </div>
      <div class="card blue">
        <div class="card-num">%d</div>
        <div class="card-label">Hosts en Red Interna</div>
      </div>
      <div class="card green">
        <div class="card-num">%d</div>
        <div class="card-label">Evidencias</div>
      </div>
    </div>
    <p style="color:var(--muted); line-height:1.8; font-size:0.9em;">
      Durante la evaluacion de seguridad se identificaron <strong style="color:var(--red)">%d
      servidor(es) JBoss vulnerable(s)</strong> que permitieron acceso no autorizado al sistema.
      Se obtuvieron <strong style="color:var(--yellow)">%d credencial(es)</strong> y se comprometieron
      <strong style="color:var(--red)">%d host(s)</strong> adicionales mediante movimiento lateral automatizado.
      El nivel de riesgo es <strong style="color:%s">%s</strong>.
    </p>
  </section>

  <!-- MAPA SVG -->
  <section class="section" id="mapa">
    <div class="section-title">◈ Mapa de Red</div>
    <div class="svg-container">%s</div>
  </section>

  <!-- VULNERABILIDADES -->
  <section class="section" id="vulnerabilidades">
    <div class="section-title">◈ Vulnerabilidades Detectadas (%d)</div>
    %s
  </section>

  <!-- COMPROMETIDOS -->
  <section class="section" id="comprometidos">
    <div class="section-title">◈ Hosts Comprometidos (%d)</div>
    %s
  </section>

  <!-- RED INTERNA -->
  <section class="section" id="red">
    <div class="section-title">◈ Servicios Red Interna (%d)</div>
    %s
  </section>

  <!-- CREDENCIALES -->
  <section class="section" id="credenciales">
    <div class="section-title">◈ Credenciales Encontradas (%d)</div>
    %s
  </section>

  <!-- EVIDENCIAS -->
  <section class="section" id="evidencias">
    <div class="section-title">◈ Evidencias (%d)</div>
    %s
  </section>

  <!-- REMEDIACION -->
  <section class="section" id="remediacion">
    <div class="section-title">◈ Recomendaciones de Remediacion</div>

    <div class="remed-block">
      <div class="remed-title">[JBoss] Eliminar consolas administrativas expuestas</div>
      <div class="remed-body">
        Remover o deshabilitar: jmx-console.war, web-console.war, admin-console.war,
        http-invoker.sar, jmx-invoker-adaptor-server.sar.<br>
        <code>$ rm jmx-console.war web-console.war admin-console.war http-invoker.sar</code>
      </div>
    </div>

    <div class="remed-block">
      <div class="remed-title">[JBoss] Restriccion de acceso a nivel de red</div>
      <div class="remed-body">
        Implementar reverse proxy (nginx, Apache, F5) con whitelist de IPs.
        Aplicar DROP INPUT POLICY en el firewall para los puertos de administracion (8080, 9990, etc.).
      </div>
    </div>

    <div class="remed-block">
      <div class="remed-title">[Deserializacion Java] Mitigacion</div>
      <div class="remed-body">
        No deserializar objetos de fuentes no confiables. Implementar whitelist con Look-ahead
        antes de deserializar. Migrar a formatos seguros como JSON/Gson donde sea posible.
        Para ViewState: cambiar STATE_SAVING_METHOD a "server" en web.xml.
      </div>
    </div>

    <div class="remed-block">
      <div class="remed-title">[Credenciales] Cambio inmediato</div>
      <div class="remed-body">
        Cambiar TODAS las credenciales encontradas en este reporte de forma inmediata.
        Implementar rotacion periodica de passwords y politica de passwords fuertes.
        Si el servidor fue comprometido: considerar descartarlo y reconstruirlo desde cero.
      </div>
    </div>

    <div class="remed-block">
      <div class="remed-title">[Red] Segmentacion</div>
      <div class="remed-body">
        Implementar segmentacion de red para aislar servidores JBoss.
        Restringir acceso a bases de datos unicamente desde IPs autorizadas.
        Monitorear accesos con SIEM y alertas en tiempo real.
      </div>
    </div>
  </section>

</main>

<div class="footer">
  PANTER JBOSS v%s &nbsp;|&nbsp; Analista: %s &nbsp;|&nbsp; %s<br>
  <span style="color:#333">Solo para uso autorizado. Toda actividad es monitoreada.</span>
</div>

<script>
function toggle(id) {
  var el = document.getElementById(id);
  el.style.display = el.style.display === 'block' ? 'none' : 'block';
}
// Smooth scroll
document.querySelectorAll('a[href^="#"]').forEach(function(a) {
  a.addEventListener('click', function(e) {
    e.preventDefault();
    document.querySelector(this.getAttribute('href')).scrollIntoView({behavior:'smooth'});
  });
});
</script>
</body>
</html>""" % (
        color_riesgo, version, nivel_riesgo,
        analyst, f_inicio, f_fin, len(hosts_scan),
        len(comprometidos), len(vulns), len(creds), len(red_interna), len(evidencias),
        len(vulns), len(creds), len(comprometidos), color_riesgo, nivel_riesgo,
        svg,
        len(vulns), tabla_vulns,
        len(comprometidos), tabla_comp,
        len(red_interna), tabla_red,
        len(creds), tabla_creds,
        len(evidencias), ev_html,
        version, analyst,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    with open(nombre_archivo, 'w', encoding='utf-8') as f:
        f.write(html)

    _p("\n" + "\033[32m" + "\033[1m" +
       "  [+] Reporte generado: %s\n" % nombre_archivo + "\033[0m")
    return nombre_archivo


def _tabla_html(headers, rows, clase=""):
    if not rows:
        return '<p style="color:#8b949e; font-size:0.9em;">Sin datos.</p>'
    ths = "".join("<th>%s</th>" % h for h in headers)
    trs = ""
    for row in rows:
        tds = "".join("<td>%s</td>" % str(c).replace('<','&lt;').replace('>','&gt;')
                      for c in row)
        trs += "<tr>%s</tr>" % tds
    return '<table class="%s"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (
        clase, ths, trs)


def _generar_svg(comprometidos, red_interna):
    """Genera un mapa SVG de la infraestructura comprometida."""
    ancho  = 900
    alto   = max(300, 120 + len(comprometidos) * 80 + len(red_interna[:8]) * 50)

    nodos = []
    # Nodo central (atacante)
    nodos.append({'x': 80,  'y': alto//2, 'label': 'KALI\n(Atacante)',
                  'color': '#39d353', 'r': 30})

    # Hosts comprometidos
    for i, h in enumerate(comprometidos[:8]):
        y = 80 + i * (alto - 160) // max(len(comprometidos), 1)
        nodos.append({'x': 400, 'y': y,
                      'label': h.get('host','')[:20],
                      'color': '#f85149', 'r': 25})

    # Servicios internos (muestra solo los primeros 8)
    for i, s in enumerate(red_interna[:8]):
        y = 60 + i * (alto - 100) // max(len(red_interna[:8]), 1)
        nodos.append({'x': 750, 'y': y,
                      'label': "%s:%s" % (s.get('ip',''), s.get('port','')),
                      'color': '#d29922', 'r': 18})

    # Construir SVG
    lineas = []
    # Lineas atacante → comprometidos
    for i in range(1, 1 + len(comprometidos[:8])):
        lineas.append('<line x1="%d" y1="%d" x2="%d" y2="%d" '
                      'stroke="#f85149" stroke-width="1.5" stroke-dasharray="6,3" opacity="0.7"/>' % (
                          nodos[0]['x'], nodos[0]['y'], nodos[i]['x'], nodos[i]['y']))
    # Lineas comprometidos → red interna
    offset = 1 + len(comprometidos[:8])
    for j in range(len(red_interna[:8])):
        if comprometidos:
            lineas.append('<line x1="%d" y1="%d" x2="%d" y2="%d" '
                          'stroke="#d29922" stroke-width="1" stroke-dasharray="4,4" opacity="0.5"/>' % (
                              nodos[1]['x'], nodos[1]['y'],
                              nodos[offset + j]['x'], nodos[offset + j]['y']))

    # Circulos y texto
    circulos = []
    for n in nodos:
        circulos.append(
            '<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.15" '
            'stroke="%s" stroke-width="2"/>' % (
                n['x'], n['y'], n['r'], n['color'], n['color']))
        for li, linea in enumerate(n['label'].split('\n')):
            circulos.append(
                '<text x="%d" y="%d" text-anchor="middle" fill="%s" '
                'font-size="10" dy="%d">%s</text>' % (
                    n['x'], n['y'] + 4, n['color'], li * 12, linea))

    svg = ('<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg" '
           'style="background:#0d1117">\n' % (ancho, alto))
    svg += '\n'.join(lineas) + '\n'
    svg += '\n'.join(circulos) + '\n'
    svg += '</svg>'
    return svg
