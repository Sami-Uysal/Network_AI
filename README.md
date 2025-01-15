# Network AI - Malicious Traffic Analysis

This project aims to build an AI-powered system for capturing and analyzing network traffic to identify malicious activity in real-time. The tool leverages machine learning models and packet analysis to enhance network security.

---

## Features

- **Real-Time Packet Analysis:** Capture and analyze live network traffic.
- **Malware Detection:** Use machine learning to classify traffic as "Normal" or "Malicious."
- **Custom Dataset Support:** Train models with your own labeled datasets for improved accuracy.
- **User-Friendly Interface:** A Tkinter-based GUI for easy interaction and visualization of results.

---

## Installation

### 1. Clone this Repository:
```bash
git clone https://github.com/username/network_ai.git
cd network_ai
```
### 2. Create and Activate a Virtual Environment:
```bash
python -m venv .venv
source .venv/bin/activate  # For Windows: .venv\Scripts\activate
```

### 3. Install the Required Libraries:
```bash
pip install -r requirements.txt
```

---

## How to Use

1. **Launch the Application:**
   ```bash
   python live_analyzer.py
   ```
2. **Start Packet Sniffing:**
   - Click "Start" to capture live network traffic.
   - Use "Browse" to analyze a pre-recorded `.pcap` file.
3. **View Analysis Results:**
   - The application classifies traffic and displays it in a structured table.
   - Use the "Details" section to inspect packet contents.
4. **Custom Model Training:**
   - Train your model with labeled datasets like UNSW-NB15 or CICIDS2017.
   - Replace the default model file (`trained_model.pkl`) with your trained model.

---

## Notes

- **Dataset Requirement:** For accurate results, use well-labeled datasets. Suggested datasets include:
  - [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
  - [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Custom Feature Extraction:** Modify `feature_extractor.py` to include additional packet features as needed.

---

## Requirements

- **Python Version:** 3.7 or higher
- **Libraries:**
  - Refer to the `requirements.txt` file for the complete list.

---

## File Structure

```plaintext
.
├── live_analyzer.py      # Main application file with the GUI
├── feature_extractor.py  # Functions for extracting packet features
├── model_loader.py       # Handles loading the pre-trained machine learning model
├── packet_analysis.py    # Core packet analysis logic
├── train_model.py        # Script for training a custom model
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
```

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## About the Project

This project was developed as part of a university course assignment. It was created entirely by me with the aim of building a network traffic analysis tool powered by machine learning. However, due to my limited knowledge and experience in this domain, I was unable to fully complete the project. While it is not fully functional, I hope it can serve as a learning resource for others or as a foundation for further development.
