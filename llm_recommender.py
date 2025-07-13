# llm_recommender.py
import google.generativeai as genai

# Initialize Gemini API
genai.configure(api_key="AIzaSyDP_EV9GMhuoNCMQv_J_nGnvgM3rjxsPMA")

def recommend_patch(cve_list, system_info=None):
    """
    Uses Gemini to summarize CVE risks and recommend patches.

    Args:
        cve_list (list): List of CVEs with cve_id, description, score, severity.
        system_info (str): Optional string for system context.

    Returns:
        str: Gemini-generated patch recommendation.
    """
    if not cve_list:
        return "✅ No known CVEs found."

    # Construct prompt
    prompt = "You are a cybersecurity expert. Analyze the following CVEs and provide:\n"
    prompt += "- A brief risk summary\n"
    prompt += "- Patch or mitigation recommendations\n"
    prompt += "- Suggested priority level (e.g., Critical, High, Medium)\n\n"

    if system_info:
        prompt += f"System context: {system_info}\n"

    for cve in cve_list:
        prompt += f"\nCVE ID: {cve['cve_id']}\n"
        prompt += f"Severity: {cve['severity']}, Score: {cve['score']}\n"
        prompt += f"Description: {cve['description']}\n"

    prompt += "\nReturn your recommendations in bullet-point format."

    # Call Gemini Pro
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"❌ Gemini error: {str(e)}"

