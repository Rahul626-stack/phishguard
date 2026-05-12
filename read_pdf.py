import sys
from pypdf import PdfReader

try:
    reader = PdfReader("c:/Users/priya/PROJECTS/Pshiguard/Phishguard Complete Architecture And Implementation Plan V2.pdf")
    text = ""
    for i, page in enumerate(reader.pages):
        text += f"--- PAGE {i+1} ---\n"
        text += page.extract_text() + "\n"
    with open("pdf_output_utf8.txt", "w", encoding="utf-8") as f:
        f.write(text)
except Exception as e:
    print(f"Error: {e}")
