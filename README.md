<div align="center">
  <h1>🛡️ QuantumBreachCloudSEK</h1>
  <p>
    <strong>QuantumBreachCloudSEK</strong> is an advanced cybersecurity intelligence and threat detection pipeline. It combines Machine Learning for network anomaly detection (using the CTU-13 botnet dataset) with automated Open Source Intelligence (OSINT) gathering to identify Remote Access Trojans (RATs) and emerging threat indicators.
  </p>
</div>

<hr>

<h2>✨ Key Features</h2>
<ul>
  <li><strong>ML-Powered Anomaly Detection:</strong> Utilizes an Isolation Forest model trained on the CTU-13 dataset to accurately detect botnet traffic and abnormal network patterns.</li>
  <li><strong>Active RAT Detection:</strong> Includes dedicated monitoring scripts (<code>rat_detector.py</code>) to identify the presence and activity of Remote Access Trojans within a network.</li>
  <li><strong>Automated OSINT Scraping:</strong> Gathers real-time threat intelligence and vulnerability discussions from community platforms like Reddit and Quora to preemptively track emerging threats.</li>
  <li><strong>IoC Management:</strong> Automated configuration and deployment of Indicators of Compromise (IoCs) to strengthen network defenses.</li>
</ul>

<hr>

<h2>🛠 Tech Stack</h2>
<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>Tools</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Machine Learning</strong></td>
      <td>
        <img src="https://img.shields.io/badge/scikit--learn-%23F7931E.svg?style=flat&logo=scikit-learn&logoColor=white" alt="Scikit-Learn">
        <img src="https://img.shields.io/badge/pandas-%23150458.svg?style=flat&logo=pandas&logoColor=white" alt="Pandas">
      </td>
    </tr>
    <tr>
      <td><strong>OSINT & Scripting</strong></td>
      <td>
        <img src="https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
        <img src="https://img.shields.io/badge/Jupyter-%23F37626.svg?style=flat&logo=Jupyter&logoColor=white" alt="Jupyter Notebook">
      </td>
    </tr>
    <tr>
      <td><strong>Data Source</strong></td>
      <td>
        <img src="https://img.shields.io/badge/Dataset-CTU--13-lightgrey?style=flat" alt="CTU-13">
      </td>
    </tr>
  </tbody>
</table>

<hr>

<h2>🚀 Getting Started</h2>

<h3>Prerequisites</h3>
<ul>
  <li>Python 3.8+</li>
  <li>Jupyter Notebook</li>
</ul>

<h3>Installation & Launch</h3>
<ol>
  <li>
    <strong>Clone the Repo</strong>
<pre><code>git clone https://github.com/internalerror69/quantumbreachcloudsek.git
cd quantumbreachcloudsek</code></pre>
  </li>
  <li>
    <strong>Install Dependencies</strong>
<pre><code>pip install scikit-learn pandas numpy jupyter</code></pre>
  </li>
  <li>
    <strong>Initialize Threat Data & Models</strong>
<pre><code>python setup_iocs.py
python train_anomoly.py</code></pre>
  </li>
  <li>
    <strong>Run Active Detection</strong>
<pre><code>python rat_detector.py</code></pre>
  </li>
</ol>

<hr>

<h2>📊 How It Works</h2>
<p>The system operates on a dual-pronged approach—internal network monitoring and external threat intelligence:</p>
<ol>
  <li><strong>Intelligence Gathering (OSINT):</strong> The Jupyter notebooks (<code>OSINT_threat.ipynb</code> and <code>redit_qora.ipynb</code>) scrape security forums and social platforms to extract trending keywords, CVEs, and attacker methodologies.</li>
  <li><strong>IoC Configuration:</strong> Extracted data and known signatures are configured into actionable rules using <code>setup_iocs.py</code>.</li>
  <li><strong>Model Training:</strong> <code>train_anomoly.py</code> processes the <code>CTU13_Combined_Cleaned.csv</code> dataset to train an <strong>Isolation Forest</strong> model, learning the baseline of normal network behavior versus botnet traffic.</li>
  <li><strong>Active Defense:</strong> Scripts like <code>converge.py</code> and <code>rat_detector.py</code> continuously apply the trained ML model (<code>isolation_forest_ctu13.pkl</code>) and IoC rules against active network streams to flag intrusions.</li>
</ol>

<hr>

<h2>📁 Repository Highlights</h2>
<ul>
  <li><code>train_anomoly.py</code>: The core training script that builds the anomaly detection model using the CTU-13 botnet dataset.</li>
  <li><code>isolation_forest_ctu13.pkl</code>: The pre-trained Scikit-Learn Isolation Forest model, ready for immediate inference.</li>
  <li><code>rat_detector.py</code>: specialized script tailored for identifying behavioral patterns associated with Remote Access Trojans.</li>
  <li><code>OSINT_threat.ipynb</code> & <code>redit_qora.ipynb</code>: Interactive notebooks for scraping, parsing, and analyzing open-source threat intelligence.</li>
  <li><code>setup_iocs.py</code>: Utility for ingesting and formatting Indicators of Compromise for the detection engines.</li>
  <li><code>CTU13_Combined_Cleaned.csv</code>: The cleaned dataset containing labeled network flow metrics used for training and validation.</li>
</ul>

<hr>

<p align="center">
  <small>MIT License &copy; 2026</small>
</p>
