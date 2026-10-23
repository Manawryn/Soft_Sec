from flask import Flask, request, jsonify
import requests
import data_exporter

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
    summary_text = data_exporter.summarize_metrics(record.get("title"), metrics_list)
    csv_data = data_exporter.format_record_to_csv(record)

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