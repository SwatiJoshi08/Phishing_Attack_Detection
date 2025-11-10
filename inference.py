from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Load the saved model and tokenizer
model_name = "./phishing_model"  # path where your trained model is saved
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

threshold = 0.8
def classify_email(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
    outputs = model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1).detach().cpu().numpy()[0]
    phishing_prob = probs[1]
    label = "⚠️ PHISHING" if phishing_prob > 0.5 else "✔️ LEGITIMATE"
    return label, phishing_prob

# Example usage
print(classify_email("Your account will be suspended. Click to verify!"))
print(classify_email("Let's meet tomorrow at 10 AM."))
