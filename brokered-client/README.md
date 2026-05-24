# brokered-client

Android TV client that calls the **proxy gateway** on port **5002** (RBAC, credits, device sessions).

Default `api_base_url`: `http://10.0.2.2:5002` (official emulator → host).

Import this folder in Android Studio. Start backend with `docker compose up --build` first.

Use customer accounts created in the proxy panel at http://localhost:5002/panel .
