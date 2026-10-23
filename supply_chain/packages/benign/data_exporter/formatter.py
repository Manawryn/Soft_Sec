import csv
import io

def format_record_to_csv(record_dict):
    """Formats a dictionary record into an RFC 4180 CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=record_dict.keys())
    writer.writeheader()
    writer.writerow(record_dict)
    return output.getvalue()

def summarize_metrics(title, values):
    """Calculates statistical summary for dataset metrics."""
    if not values:
        return f"Dataset: {title} | Empty dataset"
    mean_val = sum(values) / len(values)
    # v1.1.0: also report the range, a harmless additive improvement.
    return (f"Dataset: '{title}' | Record Count: {len(values)} | "
            f"Mean Value: {mean_val:.2f} | Range: [{min(values):.2f}, {max(values):.2f}]")
