#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, send_file
from scanner import NetworkRecon
import os

app = Flask(__name__)
app.secret_key = "votre_cle_secrete"

recon_tool = NetworkRecon()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    domain = request.form.get("domain")
    if not domain:
        return jsonify({"error": "Veuillez entrer un domaine valide."})

    # Analyse du domaine
    data = {}
    ip = recon_tool.resolve_ip(domain)
    if not ip:
        return jsonify({"error": "Domaine non résolu."})

    data["ip"] = ip
    data["reverse_dns"] = recon_tool.reverse_dns(ip)
    data["ping_rate"] = recon_tool.ping_host(domain)
    data["ttl"], data["os_guess"] = recon_tool.analyze_ttl(domain)
    data["open_ports"] = recon_tool.port_scan(ip, recon_tool.common_ports)
    data["subdomains"] = recon_tool.subdomain_scan(domain)
    data["port_graph"] = recon_tool.ascii_port_graph(data["open_ports"])

    # Génération du rapport
    report_filename = recon_tool.generate_report(domain, data)
    recon_tool.update_history(domain, data)

    return jsonify({
        "success": True,
        "data": data,
        "report": report_filename
    })

@app.route("/download/<filename>")
def download(filename):
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)