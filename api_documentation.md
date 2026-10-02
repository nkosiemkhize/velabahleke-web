# Velabahleke High School — API Documentation

Base URL (development): `http://127.0.0.1:5000`

---

## POST /api/contact

Submit a message through the school's contact form.

**Request format:** JSON

### Request Body

| Field | Type | Required | Notes |
|---|---|---|---|
| name | string | Yes | Sender's full name |
| email | string | Yes | Must look like a valid email address |
| subject | string | Yes | Subject line of the message |
| message | string | Yes | The message body |

### Responses

| Status Code | Meaning | Example Body |
|---|---|---|
| 201 | Message saved successfully | `{"success": true}` |
| 400 | A field was missing, empty, or the email was invalid | `{"error": "All fields are required."}` |
| 500 | The server failed to save the message | `{"error": "Could not save your message. Please try again."}` |

---

## GET /api/contact

Return all saved contact messages. **Development use only — not yet protected by login.**

### Responses

| Status Code | Meaning | Example Body |
|---|---|---|
| 200 | List of saved messages | `{"messages": [ ... ]}` |

---

## POST /api/enrolment

Submit a Grade 8 enrolment application, including two file uploads.

**Request format:** multipart/form-data (required because of the file uploads)

### Request Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| fullName | string | Yes | Applicant's full name |
| ParentName | string | Yes | Parent/guardian's full name |
| PhoneNumber | string | Yes | Contact phone number |
| email | string | Yes | Must look like a valid email address |
| report | file | Yes | PDF, JPG, or PNG. Max size 5 MB |
| idCopy | file | Yes | PDF, JPG, or PNG. Max size 5 MB |

### Responses

| Status Code | Meaning | Example Body |
|---|---|---|
| 201 | Application saved successfully | `{"success": true}` |
| 400 | A required field/file was missing, invalid, wrong type, or too large | `{"error": "The school report must be a PDF, JPG, or PNG file."}` |
| 500 | The server failed to save the files or the application record | `{"error": "Could not save your application. Please try again."}` |

---

## GET /api/enrolment

Return all saved enrolment applications. **Development use only — not yet
protected by login. Contains personal information about minors; must be
secured before real deployment.**

### Responses

| Status Code | Meaning | Example Body |
|---|---|---|
| 200 | List of saved enrolment applications | `{"enrolments": [ ... ]}` |

---

## Known Limitations (see app.py for full detail)

| Issue | Impact |
|---|---|
| No authentication on GET endpoints | Anyone with the URL can view all submissions |
| No rate limiting | Form could be spammed with repeated submissions |
| File type checked by extension only | A renamed file could bypass the type check |
| JSON file storage, not a database | Two submissions at the same moment could overwrite each other |
