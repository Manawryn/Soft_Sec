from flask import Flask, request, jsonify
import requests
from sandboxed_dependency import call_sandboxed

app = Flask(__name__)
RESOURCE_SERVICE_URL = "http://127.0.0.1:5002"

@app.route("/process/export", methods=["POST"])
def export_job():
    payload = request.get_json() or {}
    dataset_id = payload.get("dataset_id")
    auth_header = request.headers.get("Authorization")

    if not dataset_id or not auth_header:
        return jsonify({"error": "dataset_id and Authorization required"}), 400

    # FIX 4: Forward the user's scoped token instead of using an ambient internal key
    headers = {"Authorization": auth_header}
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/dataset/{dataset_id}", headers=headers, timeout=3)

    if res.status_code != 200:
        return jsonify({"error": "Failed to fetch dataset. Access denied."}), res.status_code

    record = res.json()
    metrics_list = [float(x.strip()) for x in record.get("metrics", "").split(",") if x.strip()]

    # FIX 5 (TH-05 / Boundary B4): the data_exporter dependency never runs
    # in this process. Every call is isolated in a child process with an
    # empty working directory and no outbound network, so even a
    # compromised build that was mistakenly approved by the integrity gate
    # (supply_chain/manifest.json) cannot read a real project file or
    # exfiltrate anything over the network - see
    # processing_service/sandboxed_dependency.py and
    # supply_chain/run_experiment_B.py.
    try:
        summary_text = call_sandboxed("summarize_metrics", title=record.get("title"), values=metrics_list)
        csv_data = call_sandboxed("format_record_to_csv", record=record)
    except RuntimeError as e:
        return jsonify({"error": f"Export failed: dependency sandbox violation ({e})"}), 502

    # Save the artifact back to the Resource Service using the SAME
    # job-scoped token (still bound to this dataset/action/validity period)
    # instead of returning it inline; the user retrieves it separately.
    save_res = requests.post(f"{RESOURCE_SERVICE_URL}/resources/exports",
                              headers=headers,
                              json={"dataset_id": dataset_id, "summary": summary_text, "csv_data": csv_data},
                              timeout=3)
    if save_res.status_code != 201:
        return jsonify({"error": "Failed to save export"}), save_res.status_code

    return jsonify({
        "status": "COMPLETED",
        "dataset_id": dataset_id,
        "export_id": save_res.json()["export_id"]
    }), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)