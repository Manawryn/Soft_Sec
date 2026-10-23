from flask import Flask, request, jsonify
import requests
import data_exporter

app = Flask(__name__)

RESOURCE_SERVICE_URL = "http://127.0.0.1:5002"
INTERNAL_KEY = "processing-engine-internal-secret"

# VULNERABILITY 4 (Composition Flaw: Confused Deputy - CWE-441)
@app.route("/process/export", methods=["POST"])
def export_job():
    payload = request.get_json() or {}
    dataset_id = payload.get("dataset_id")

    if not dataset_id:
        return jsonify({"error": "dataset_id required"}), 400

    # INTENTIONAL FLAW: Uses its own privileged ambient internal key to request the record
    # without forwarding or validating the original user's authority for this specific dataset
    headers = {"X-Internal-Service": INTERNAL_KEY}
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/internal/dataset/{dataset_id}", headers=headers, timeout=3)

    if res.status_code != 200:
        return jsonify({"error": "Failed to fetch dataset from Resource Service"}), res.status_code

    record = res.json()

    # Computation using the external package
    metrics_list = [float(x.strip()) for x in record.get("metrics", "").split(",") if x.strip()]
    summary_text = data_exporter.summarize_metrics(record.get("title"), metrics_list)
    csv_data = data_exporter.format_record_to_csv(record)

    # Save the artifact back to the Resource Service instead of returning it
    # inline (assignment Figure 1); the user retrieves it separately.
    save_res = requests.post(f"{RESOURCE_SERVICE_URL}/resources/internal/exports",
                              headers=headers,
                              json={"dataset_id": dataset_id, "summary": summary_text, "csv_data": csv_data},
                              timeout=3)
    export_id = save_res.json().get("export_id") if save_res.status_code == 201 else None

    return jsonify({
        "status": "COMPLETED",
        "dataset_id": dataset_id,
        "classification": record.get("classification"),
        "export_id": export_id
    }), 200

if __name__ == "__main__":
    print("[*] Starting Processing Service on port 5003...")
    app.run(host="127.0.0.1", port=5003, debug=False)