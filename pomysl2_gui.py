import streamlit as st
import requests
import csv
import base64
import os
from dotenv import load_dotenv
import zipfile
import tempfile

load_dotenv()

WAZUH_API_URL = "https://wazuh.allclouds.pl:55000"
VERIFY_SSL = False
EXCLUDED_PACKAGES = ["Dolby Audio X2 Windows APP","Microsoft Update Health Tools","Środowisko uruchomieniowe Microsoft Edge WebView2","Paint 3D","Kontakty", "Centrum opinii", "Uzyskaj pomoc", "Wycinek i szkic", "Kalendarz", "Instalator aplikacji","Microsoft Store", "Odtwarzacz multimedialny", "Aparat", "Wskazówki", "Zegar", "Xbox Live","Office 16 Click-to-Run Localization Component", "Host środowiska sklepu Store", "Pogoda", "Game Bar","Xbox Identity Provider", "Przeglądarka 3D", "Mapy", "Solitaire & Casual Games", "Xbox Game bar","Oprogramowanie mikroukładu Intel", "Xbox Game Speech Windows", "Rejestrator głosu", "Kalkulator", "Copilot","Zdjęcia"]
username=os.getenv('NAME')
password=os.getenv('PASSWORD')

def export_all_agents_packages_to_zip(token, agents, selected_columns):
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "wazuh_all_agents.zip")

    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for agent in agents:
            try:
                agent_id = agent["id"]
                agent_name = agent["name"].replace(" ", "_")
                packages = get_packages(token, agent_id)
                filtered = [pkg for pkg in packages if pkg["name"] not in EXCLUDED_PACKAGES]

                if not filtered:
                    continue

                csv_file_path = os.path.join(temp_dir, f"{agent_name}_{agent_id}.csv")
                with open(csv_file_path, mode='w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=selected_columns)
                    writer.writeheader()
                    for pkg in filtered:
                        row = {col: pkg.get(col, "-") for col in selected_columns}
                        writer.writerow(row)

                zipf.write(csv_file_path, arcname=os.path.basename(csv_file_path))

            except Exception as e:
                print(f"Error processing agent {agent['name']}: {e}")

    return zip_path


def get_agents(token):
    url = WAZUH_API_URL + "/agents?pretty=true&sort=-ip,name"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json().get("data", {}).get("affected_items", [])

def get_token():
    url = WAZUH_API_URL + "/security/user/authenticate?raw=true"
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, verify=VERIFY_SSL)
    response.raise_for_status()

    token = response.text.strip()
    return token

def get_packages(token, agent_id):
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/packages?limit=1000"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json().get("data", {}).get("affected_items", [])

def export_packages_to_csv(packages, columns):
    filtered = [pkg for pkg in packages if pkg["name"] not in EXCLUDED_PACKAGES]
    csv_file = filename = f"wazuh_packages_{agent_id}.csv"
    with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for pkg in filtered:
            row = {col: pkg.get(col, "-") for col in columns}
            writer.writerow(row)
    return csv_file

st.title("Generator raportów wazuh")
token = get_token()
agents = get_agents(token)
st.sidebar.header("Lista agentów:")
for agent in agents:
    st.sidebar.subheader(agent["name"])
    st.sidebar.write("ID: " + agent["id"])
    st.sidebar.write("Status: "+agent["status"])
    st.sidebar.write("Platform: "+agent["os"]["platform"])

agent_options = {f"{agent['name']} (ID: {agent['id']})": agent["id"] for agent in agents}
selected_agent = st.selectbox("Wybierz agenta:", options=list(agent_options.keys()))
agent_id = agent_options.get(selected_agent)


if token and agent_id:
    try:
        with st.spinner("Pobieranie danych..."):
            data = get_packages(token, agent_id)

        if not data:
            st.warning("Nie znaleziono pakietów dla danego agenta.")
        else:
            all_keys = set()
            for item in data:
                all_keys.update(item.keys())
            all_keys = sorted(all_keys)

            selected_columns = st.multiselect("Wybierz kolumny do eksportu:", options=all_keys, default=["name"])
            if data:
                preview_data = [{col: pkg.get(col, "-") for col in selected_columns} for pkg in data if
                                pkg["name"] not in EXCLUDED_PACKAGES]
                st.dataframe(preview_data)

            if st.button("Wygeneruj raport"):
                if not selected_columns:
                    st.error("Wybierz przynajmniej jedną kolumnę.")
                else:
                    csv_file = export_packages_to_csv(data, selected_columns)
                    st.success(f"Raport został wygenerowany jako: {csv_file}")
                    with open(csv_file, "rb") as f:
                        st.download_button("Pobierz plik CSV", f, file_name="wazuh_packages.csv")
            st.markdown("---")
            st.subheader("Eksport danych pakietów ze wszystkich agentów")

            if st.button("Wygeneruj ZIP ze wszystkimi agentami"):
                if not selected_columns:
                    st.error("Wybierz kolumny do eksportu przed generowaniem ZIPa.")
                else:
                    with st.spinner("Generowanie raportów..."):
                        zip_file_path = export_all_agents_packages_to_zip(token, agents, selected_columns)
                    with open(zip_file_path, "rb") as f:
                        st.download_button(
                            label="Pobierz ZIP",
                            data=f,
                            file_name="wazuh_agents_packages.zip",
                            mime="application/zip"
                        )


    except Exception as e:
        st.error(f"Błąd: {str(e)}")

#to run:
#streamlit run pomysl2_gui.py

#zeby mozna wyblo wubierac kolumny
#dodac zeby dostawac token w kodzie
#wyswietlac id agenta i nazwe

#dodac opcje ktora bedzie potrzebna
#dodac plik requirements
