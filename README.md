# PACT • Police Assist Case Trace
### Advanced Law Enforcement Command & Case Intelligence Platform

PACT (Police Assist Case Trace) is a secure, role-based law enforcement case tracking, evidence cataloging, and crime intelligence management platform.

---

## 🔐 Synthetic Demo Credentials & Personnel Directory

Use these credentials to authenticate into the system for evaluation, role testing, and verification:

| Officer ID | Role | Name | Assigned Station | Standard Password |
| :--- | :--- | :--- | :--- | :--- |
| `TS-POL-001` | **SP** | Vikramaditya Varma, IPS | Cyberabad Central (`STN-001`) | `Pact@Officer2026!` |
| `TS-POL-002` | **SP** | Dr. Ananya Deshmukh, IPS | Punjagutta Command (`STN-008`) | `Pact@Officer2026!` |
| `TS-POL-003` | **SI** | Rajeshwar Rao | Banjara Hills (`STN-002`) | `Pact@Officer2026!` |
| `TS-POL-004` | **SI** | Pradeep K. Reddy | Madhapur IT (`STN-003`) | `Pact@Officer2026!` |
| `TS-POL-005` | **SI** | Sunita G. Naidu | Cyber Crime Div (`STN-004`) | `Pact@Officer2026!` |
| `TS-POL-006` | **IO** | K. Vamsi Krishna | Cyber Crime Div (`STN-004`) | `Pact@Officer2026!` |
| `TS-POL-007` | **IO** | Sneha Patel | Banjara Hills (`STN-002`) | `Pact@Officer2026!` |
| `TS-POL-008` | **IO** | T. Arvind Chary | Madhapur IT (`STN-003`) | `Pact@Officer2026!` |
| `TS-POL-009` | **IO** | Meera Varma | Jubilee Hills (`STN-007`) | `Pact@Officer2026!` |
| `TS-POL-010` | **CONSTABLE** | D. Suresh Kumar | Cyberabad Central (`STN-001`) | `Pact@Officer2026!` |
| `TS-POL-011` | **CONSTABLE** | B. Ramesh Goud | Cyber Crime Div (`STN-004`) | `Pact@Officer2026!` |
| `TS-POL-012` | **ADMIN** | System Administrator | State IT Directorate (`STN-008`) | `Pact@Admin2026!` |

> **Note**: Accounts lock automatically after 5 consecutive failed login attempts. Unlocking requires administrator intervention.

---

## 🚀 Running the Platform

1. **Prerequisites**:
   - Python 3.10+
   - MongoDB running locally on `mongodb://localhost:27017/` (or configured via `MONGO_URI` in `.env`)

2. **Environment Configuration**:
   Create a `.env` file from `.env.example`:
   ```bash
   MONGO_URI=mongodb://localhost:27017/
   MONGO_DB_NAME=pact_db
   ENVIRONMENT=development
   MAX_LOGIN_ATTEMPTS=5
   PASSWORD_MIN_LENGTH=12
   SESSION_EXPIRY_MINUTES=480
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

3. **Start Streamlit Server**:
   ```bash
   streamlit run app.py
   ```
   Open your browser at `http://localhost:8501`.

---

## 🛡️ Role-Based Access Control (RBAC) Architecture

- **`ADMIN`**: State IT Directorate. Full department-wide administrative access, user lockout management, station registry management, and immutable audit telemetry inspection.
- **`SP` (Superintendent of Police)**: Executive departmental oversight across all 10 police stations. Exclusively holds access to the **Consolidated Crime Analytics & Tactical Mapping Center**, audit trail, and executive reporting.
- **`SI` (Sub-Inspector)**: Station-level operational command. Can register FIRs, view station case dossiers, assign lead investigators, and review case milestones.
- **`INVESTIGATING_OFFICER` (IO)**: Lead detective. Strictly manages assigned cases, case diaries, evidence uploads, custody logging, and AI case intelligence.
- **`CONSTABLE`**: Patrol officer. Permitted to register and lodge First Information Reports (FIRs), inspect basic assigned cases, and record beat logs.

---

## 🧪 Running Automated Tests

Run the full regression test suite:
```bash
pytest tests/
```
