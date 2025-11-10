import pandas as pd
import torch
import evaluate
from sklearn.model_selection import train_test_split
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Step 1–3: Load and clean dataset
csv_path = "archive/spam.csv"
df = pd.read_csv(csv_path, encoding='latin-1')
df = df[['v1', 'v2']]
df = df.rename(columns={"v1": "label", "v2": "text"})
df['label'] = df['label'].map({'ham': 0, 'spam': 1})

print("Sample cleaned data:")
print(df.head())
print("\nLabel counts:")
print(df['label'].value_counts())

# Step 4: Train-validation split
texts = df['text'].tolist()
labels = df['label'].tolist()

train_texts, val_texts, train_labels, val_labels = train_test_split(
    texts, labels, test_size=0.2, random_state=42
)

# ✅ Step 5: Load pretrained tokenizer and model
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

# Step 6: Tokenize the text data
train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=512)
val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=512)

# Step 7: Create Dataset class
class EmailDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels
    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item
    def __len__(self):
        return len(self.labels)

# Create dataset objects
train_dataset = EmailDataset(train_encodings, train_labels)
val_dataset = EmailDataset(val_encodings, val_labels)

# Step 8
from transformers import Trainer, TrainingArguments

metric = evaluate.load("accuracy")

# Define compute_metrics function for evaluation
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = logits.argmax(axis=-1)
    return metric.compute(predictions=predictions, references=labels)

# Define training arguments
training_args = TrainingArguments(
    output_dir="./phishing_model",          # where to save the model
    num_train_epochs=3,                     # total training epochs
    per_device_train_batch_size=8,          # batch size for training
    per_device_eval_batch_size=8,           # batch size for evaluation
    evaluation_strategy="epoch",            # evaluate each epoch
    save_strategy="epoch",                  # save model each epoch
    logging_dir="./logs",                   # where to log metrics
    logging_steps=10,                       # log every 10 steps
)

# Step 9: Create Trainer and start training
from transformers import Trainer

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics
)

trainer.train()

# Save the trained model and tokenizer locally
model.save_pretrained("./phishing_model")
tokenizer.save_pretrained("./phishing_model")
