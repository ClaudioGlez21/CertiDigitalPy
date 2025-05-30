import streamlit as st
from streamlit_option_menu import option_menu
import hashlib
import base64
from datetime import datetime, timezone
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from google.cloud import firestore
from google.oauth2 import service_account
import json

st.set_page_config(page_title="CertiDigital", layout="wide", page_icon="🎓")

FIRESTORE_COLLECTION_NAME = "diplomas_certificados"
DB_INITIALIZED = False
db = None

try:
    # Intenta cargar las credenciales desde secretos de Streamlit (preferido para despliegue)
    firestore_creds_json = st.secrets.get("firestore", {}).get("credentials_json")
    if firestore_creds_json:
        creds_dict = json.loads(firestore_creds_json)
        credentials = service_account.Credentials.from_service_account_info(creds_dict)
        db = firestore.Client(credentials=credentials)
        DB_INITIALIZED = True
        st.sidebar.success("Conectado a Firestore (Secrets).")
    else:
        local_creds_path = "firestore_credentials.json" # Asegúrate que este archivo esté en .gitignore
        if os.path.exists(local_creds_path):
            db = firestore.Client.from_service_account_json(local_creds_path)
            DB_INITIALIZED = True
            # st.sidebar.info("Conectado a Firestore (Local JSON).")
        else:
            st.sidebar.error("Credenciales de Firestore no configuradas. La funcionalidad de base de datos está deshabilitada.")
            # st.sidebar.caption("Crea 'firestore_credentials.json' o configura secretos en Streamlit Cloud.")

except Exception as e:
    st.sidebar.error(f"Error al conectar con Firestore: {str(e)[:100]}...")
    # st.sidebar.caption("Verifica la configuración de credenciales.")


# --- Gestión de Claves y Certificado de la Organización ---
ORG_PRIVATE_KEY_FILE = "organizational_private_key.pem"
ORG_CERTIFICATE_FILE = "organizational_certificate.pem"
ORG_KEY_PASSWORD_STR = st.secrets.get("org_identity", {}).get("key_password", "Password_demo")

def generate_and_save_org_keys_and_cert():
    """Genera y guarda la clave privada y el certificado autofirmado de la organización si no existen."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(ORG_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(ORG_KEY_PASSWORD)
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jalisco"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Guadalajara"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Organización Educativa Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"certidigital.example.com"),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + datetime.timedelta(days=365)) # Válido por 1 año
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    with open(ORG_CERTIFICATE_FILE, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    return private_key, certificate

def load_org_keys_and_cert():
    """Carga la clave privada y el certificado de la organización. Los genera si no existen."""
    if not os.path.exists(ORG_PRIVATE_KEY_FILE) or not os.path.exists(ORG_CERTIFICATE_FILE):
        st.sidebar.warning("Generando nuevas claves y certificado para la organización...")
        private_key, certificate = generate_and_save_org_keys_and_cert()
        st.sidebar.success("Claves y certificado generados.")
    else:
        with open(ORG_PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=ORG_KEY_PASSWORD,
            )
        with open(ORG_CERTIFICATE_FILE, "rb") as f:
            certificate = x509.load_pem_x509_certificate(f.read())
    return private_key, certificate

# Cargar (o generar) al inicio
ORG_PRIVATE_KEY, ORG_CERTIFICATE = load_org_keys_and_cert()
ORG_CERTIFICATE_PEM_STR = ORG_CERTIFICATE.public_bytes(serialization.Encoding.PEM).decode('utf-8')

# --- Funciones Criptográficas ---
def hash_document(document_bytes):
    """Calcula el hash SHA-256 de un documento."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(document_bytes)
    return sha256_hash.digest() # Devuelve bytes crudos del hash

def sign_hash(data_hash, private_key):
    """Firma un hash usando la clave privada."""
    signature = private_key.sign(
        data_hash,
        padding.PKCS1v15(), # Esquema de padding común
        hashes.SHA256()
    )
    return signature

def verify_signature(data_hash, signature, public_key):
    """Verifica una firma usando la clave pública."""
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# --- Funciones de Base de Datos (Firestore) ---
def store_certificate_details(curp, diploma_filename, diploma_hash_hex, signature_b64, certificate_pem_str):
    """Almacena los detalles del certificado en Firestore."""
    if not DB_INITIALIZED or db is None:
        st.error("Error: Base de datos no inicializada. No se puede guardar.")
        return None
    try:
        timestamp = datetime.now(timezone.utc)
        doc_ref = db.collection(FIRESTORE_COLLECTION_NAME).document()
        doc_data = {
            "curp": curp.upper(),
            "diploma_filename": diploma_filename,
            "diploma_hash_hex": diploma_hash_hex,
            "signature_b64": signature_b64,
            "certificate_pem": certificate_pem_str, 
            "issuer_info": ORG_CERTIFICATE.subject.rfc4514_string(),
            "timestamp": timestamp,
            "firestore_doc_id": doc_ref.id # Guardamos el ID para referencia
        }
        doc_ref.set(doc_data)
        return doc_data # Devuelve los datos guardados, incluyendo el ID
    except Exception as e:
        st.error(f"Error al guardar en Firestore: {e}")
        return None

def get_certificate_details_by_curp(curp):
    """Obtiene detalles de certificados para un CURP desde Firestore."""
    if not DB_INITIALIZED or db is None:
        st.error("Error: Base de datos no inicializada. No se puede consultar.")
        return []
    try:
        query = db.collection(FIRESTORE_COLLECTION_NAME).where("curp", "==", curp.upper()).stream()
        results = [doc.to_dict() for doc in query]
        return results
    except Exception as e:
        st.error(f"Error al consultar Firestore: {e}")
        return []

# --- Interfaz de Usuario Streamlit ---
st.markdown("""
<style>
    .main .block-container {
        padding-top: 2rem;
    }
    .stButton>button {
        border-radius: 20px;
        border: 1px solid #2E7D32; /* Verde oscuro */
        background-color: #4CAF50; /* Verde */
        color: white;
        padding: 10px 24px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
    }
    .stButton>button:hover {
        background-color: #388E3C; /* Verde más oscuro */
        color: white;
        border: 1px solid #1B5E20;
    }
    .stTextInput input {
        border-radius: 10px;
    }
    .stFileUploader label {
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.image("https://placehold.co/600x100/00796b/FFFFFF?text=CertiDigital+🎓&font=raleway", use_column_width=True)
# st.title("🎓 CertiDigital: Plataforma de Certificación")
# st.markdown("---")


with st.sidebar:
    st.markdown("## Navegación")
    selected = option_menu(
        menu_title=None,  # required
        options=["Emitir Certificado", "Verificar Certificado", "Info del Sistema"],
        icons=["award", "patch-check", "info-circle"],  # optional
        menu_icon="cast",  # optional
        default_index=0,  # optional
    )
    st.markdown("---")
    st.markdown(f"**Emisor del Certificado:**")
    st.caption(f"{ORG_CERTIFICATE.subject.rfc4514_string()}")
    st.markdown(f"**Válido hasta:**")
    st.caption(f"{ORG_CERTIFICATE.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    st.markdown("---")
    if DB_INITIALIZED:
        st.success("Conexión a BD activa.")
    else:
        st.warning("Conexión a BD inactiva.")


if selected == "Emitir Certificado":
    st.header("✍️ Emitir Nuevo Certificado Digital")
    st.markdown("Cargue el diploma (preferiblemente PDF) y proporcione el CURP del participante.")

    with st.form("emitir_form"):
        curp_input = st.text_input("CURP del Participante:", max_chars=18, help="Clave Única de Registro de Población.")
        uploaded_file = st.file_uploader("Seleccione el Diploma:", type=['pdf', 'png', 'jpg', 'jpeg'], help="Formatos soportados: PDF, PNG, JPG.")
        submit_button = st.form_submit_button("Generar y Firmar Certificado")

    if submit_button:
        if not curp_input:
            st.warning("⚠️ Por favor, ingrese el CURP.")
        elif not uploaded_file:
            st.warning("⚠️ Por favor, cargue el archivo del diploma.")
        elif not DB_INITIALIZED:
            st.error("❌ No se puede emitir: la conexión con la base de datos no está activa.")
        else:
            curp = curp_input.strip().upper()
            if len(curp) != 18: # Validación simple de longitud
                 st.warning("⚠️ El CURP debe tener 18 caracteres.")
            else:
                try:
                    st.info(f"Procesando diploma para CURP: {curp}...")
                    diploma_bytes = uploaded_file.getvalue()
                    diploma_filename = uploaded_file.name

                    # 1. Hash del documento
                    doc_hash_bytes = hash_document(diploma_bytes)
                    doc_hash_hex = doc_hash_bytes.hex()

                    # 2. Firmar el hash
                    signature_bytes = sign_hash(doc_hash_bytes, ORG_PRIVATE_KEY)
                    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

                    # 3. Almacenar en Firestore
                    with st.spinner("Guardando en la base de datos..."):
                        stored_data = store_certificate_details(
                            curp,
                            diploma_filename,
                            doc_hash_hex,
                            signature_b64,
                            ORG_CERTIFICATE_PEM_STR
                        )

                    if stored_data:
                        st.success(f"✅ ¡Diploma para {curp} ({diploma_filename}) certificado con éxito!")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.download_button(
                                label="📥 Descargar Firma (.sig)",
                                data=signature_bytes,
                                file_name=f"{curp}_{diploma_filename}.sig",
                                mime="application/octet-stream"
                            )
                        with col2:
                             st.download_button(
                                label="📜 Descargar Certificado Emisor (.pem)",
                                data=ORG_CERTIFICATE_PEM_STR.encode('utf-8'),
                                file_name="certificado_organización.pem",
                                mime="application/x-x509-ca-cert" # O application/octet-stream
                            )
                        
                        st.markdown("---")
                        st.subheader("Detalles del Registro:")
                        st.json({
                            "CURP": stored_data["curp"],
                            "Nombre Archivo": stored_data["diploma_filename"],
                            "Hash SHA-256 (Diploma)": stored_data["diploma_hash_hex"],
                            "Firma Digital (Base64)": stored_data["signature_b64"][:60] + "...", # Acortado para display
                            "Certificado Emisor (Fragmento)": stored_data["certificate_pem"][:100] + "...",
                            "Fecha Emisión (UTC)": stored_data["timestamp"].strftime('%Y-%m-%d %H:%M:%S'),
                            "ID Documento Firestore": stored_data["firestore_doc_id"]
                        })
                        st.info("ℹ️ Importante: Guarde el diploma original junto con el archivo de firma (.sig) y el certificado (.pem) descargados.")
                    else:
                        st.error("❌ Hubo un problema al guardar la información del certificado.")

                except Exception as e:
                    st.error(f"Ocurrió un error durante el proceso de emisión: {e}")


elif selected == "Verificar Certificado":
    st.header("🔍 Verificar Autenticidad de Diploma")

    verification_method = st.radio(
        "Método de Verificación:",
        ("Consultar por CURP en Base de Datos", "Verificar con Archivos Locales"),
        horizontal=True
    )
    st.markdown("---")

    if verification_method == "Consultar por CURP en Base de Datos":
        st.subheader("Consultar Registro por CURP")
        if not DB_INITIALIZED:
            st.error("❌ No se puede verificar: la conexión con la base de datos no está activa.")
        else:
            curp_to_verify = st.text_input("Ingrese el CURP a verificar:", max_chars=18)
            
            st.markdown("**Opcional:** Para validar el contenido del diploma, cárguelo aquí:")
            diploma_to_check_content = st.file_uploader("Diploma Original para comparar Hash:", type=['pdf', 'png', 'jpg', 'jpeg'], key="verify_curp_diploma")

            if st.button("Buscar y Verificar por CURP"):
                if not curp_to_verify:
                    st.warning("⚠️ Por favor, ingrese un CURP.")
                else:
                    curp = curp_to_verify.strip().upper()
                    results = get_certificate_details_by_curp(curp)
                    if not results:
                        st.error(f"❌ No se encontraron registros de certificados para el CURP: {curp}")
                    else:
                        st.success(f"Se encontraron {len(results)} registro(s) para el CURP: {curp}")
                        for idx, record in enumerate(results):
                            st.markdown(f"--- \n#### Registro {idx+1}")
                            st.json({
                                "Nombre Archivo Registrado": record.get("diploma_filename"),
                                "Fecha Emisión (UTC)": record.get("timestamp").strftime('%Y-%m-%d %H:%M:%S') if record.get("timestamp") else "N/A",
                                "Hash Almacenado": record.get("diploma_hash_hex"),
                                "ID Documento Firestore": record.get("firestore_doc_id")
                            })

                            # Cargar clave pública del certificado emisor (debería ser siempre el mismo)
                            try:
                                cert_pem_str = record.get("certificate_pem")
                                if not cert_pem_str:
                                    st.error("No se encontró el PEM del certificado en el registro.")
                                    continue
                                
                                cert_obj = x509.load_pem_x509_certificate(cert_pem_str.encode('utf-8'))
                                public_key = cert_obj.public_key()

                                # Verificar firma contra hash almacenado
                                signature_b64 = record.get("signature_b64")
                                stored_hash_bytes = bytes.fromhex(record.get("diploma_hash_hex"))
                                signature_bytes = base64.b64decode(signature_b64)

                                is_signature_valid_for_stored_hash = verify_signature(stored_hash_bytes, signature_bytes, public_key)
                                if is_signature_valid_for_stored_hash:
                                    st.success("✅ FIRMA VÁLIDA: La firma digital corresponde al hash almacenado del diploma.")
                                else:
                                    st.error("❌ FIRMA INVÁLIDA: La firma digital NO corresponde al hash almacenado.")

                                # Si el usuario cargó un diploma, comparar su hash
                                if diploma_to_check_content:
                                    uploaded_diploma_bytes = diploma_to_check_content.getvalue()
                                    current_diploma_hash_bytes = hash_document(uploaded_diploma_bytes)
                                    current_diploma_hash_hex = current_diploma_hash_bytes.hex()
                                    st.markdown(f"**Hash del diploma cargado:** `{current_diploma_hash_hex}`")
                                    if current_diploma_hash_bytes == stored_hash_bytes:
                                        st.success("✅ CONTENIDO COINCIDENTE: El diploma cargado tiene el mismo hash que el registrado.")
                                    else:
                                        st.warning("⚠️ CONTENIDO DIFERENTE: El diploma cargado NO coincide con el hash del diploma originalmente firmado.")
                                else:
                                    st.info("ℹ️ Para verificar el contenido del diploma, cárguelo en el campo de arriba.")
                            except Exception as e_verify:
                                st.error(f"Error durante la verificación del registro {idx+1}: {e_verify}")


    elif verification_method == "Verificar con Archivos Locales":
        st.subheader("Verificar Diploma Usando Archivos")
        st.markdown("Cargue el diploma original, el archivo de firma (.sig) y el certificado del emisor (.pem).")

        original_diploma_file = st.file_uploader("1. Diploma Original (.pdf, .png, .jpg):", type=['pdf', 'png', 'jpg', 'jpeg'], key="local_pdf")
        signature_file = st.file_uploader("2. Archivo de Firma (.sig):", type=["sig"], key="local_sig")
        certificate_file = st.file_uploader("3. Archivo de Certificado del Emisor (.pem):", type=["pem"], key="local_pem")

        if st.button("Verificar Archivos Localmente"):
            if not all([original_diploma_file, signature_file, certificate_file]):
                st.warning("⚠️ Por favor, cargue los tres archivos requeridos para la verificación local.")
            else:
                try:
                    # Leer archivos
                    diploma_bytes = original_diploma_file.getvalue()
                    signature_bytes = signature_file.getvalue()
                    cert_pem_bytes = certificate_file.getvalue()

                    # Cargar certificado y extraer clave pública
                    cert_obj = x509.load_pem_x509_certificate(cert_pem_bytes)
                    public_key = cert_obj.public_key()
                    st.markdown(f"**Certificado Cargado Emisor:** `{cert_obj.subject.rfc4514_string()}`")
                    st.markdown(f"**Válido desde:** `{cert_obj.not_valid_before_utc.strftime('%Y-%m-%d')}` **hasta:** `{cert_obj.not_valid_after_utc.strftime('%Y-%m-%d')}`")


                    # Calcular hash del diploma cargado
                    current_diploma_hash_bytes = hash_document(diploma_bytes)
                    st.markdown(f"**Hash del Diploma Cargado:** `{current_diploma_hash_bytes.hex()}`")

                    # Verificar firma
                    is_valid = verify_signature(current_diploma_hash_bytes, signature_bytes, public_key)

                    if is_valid:
                        st.success("✅ VERIFICADO LOCALMENTE: La firma digital es válida para el diploma y certificado proporcionados.")
                        st.balloons()
                    else:
                        st.error("❌ VERIFICACIÓN LOCAL FALLIDA: La firma digital NO es válida o no corresponde a los archivos.")
                    
                    st.info("ℹ️ Esta verificación local NO confirma que el diploma esté registrado en la base de datos central.")

                except Exception as e:
                    st.error(f"Ocurrió un error durante la verificación local: {e}")

elif selected == "Info del Sistema":
    st.header("ℹ️ Información del Sistema de Certificación")
    st.markdown("""
    Esta aplicación demuestra un flujo básico para la firma digital y certificación de diplomas.
    Utiliza criptografía de clave pública (RSA) para generar firmas y certificados X.509.

    **Componentes Clave:**
    - **Hashing (SHA-256):** Para crear una huella digital única del diploma.
    - **Firma Digital (RSA con padding PKCS1v15):** El hash se cifra con la clave privada de la organización.
    - **Certificado X.509:** Contiene la clave pública de la organización y su identidad, permitiendo a terceros verificar la firma. En este demo, la organización usa un certificado autofirmado.
    - **Base de Datos (Firestore):** Almacena de forma segura los detalles de los diplomas certificados (CURP, hash, firma, certificado del emisor).

    **Flujo de Emisión:**
    1. Usuario carga diploma y CURP.
    2. Se calcula el hash del diploma.
    3. El hash se firma con la clave privada de la organización.
    4. Los detalles (CURP, hash, firma, certificado de la organización) se guardan en Firestore.
    5. El usuario puede descargar la firma y el certificado de la organización.

    **Flujo de Verificación:**
    - **Por CURP:** Se consulta la base de datos. Si se encuentra el registro, se verifica la firma almacenada contra el hash almacenado. Opcionalmente, se puede cargar el diploma original para comparar su hash con el almacenado.
    - **Local:** Se cargan el diploma, la firma y el certificado. Se verifica la firma sin consultar la base de datos.

    **Seguridad de Claves:**
    - La **clave privada de la organización (`organizational_private_key.pem`)** es CRÍTICA. Debe protegerse rigurosamente. En esta demo, se genera y guarda localmente (cifrada con contraseña), pero en un sistema real, se usarían HSMs (Hardware Security Modules) o servicios de gestión de claves.
    - La contraseña de la clave privada (`ORG_KEY_PASSWORD`) también debe ser segura y gestionada adecuadamente.
    - El **certificado de la organización (`organizational_certificate.pem`)** es público.

    **Consideraciones para Producción:**
    - Uso de una Autoridad Certificadora (CA) reconocida en lugar de certificados autofirmados.
    - Gestión robusta y segura de claves privadas.
    - Auditorías de seguridad.
    - Políticas de revocación de certificados.
    - Escalabilidad y alta disponibilidad de la base de datos.
    """)
    st.markdown("---")
    st.subheader("Certificado de la Organización Emisora (Actual)")
    try:
        st.text_area("Detalles del Certificado (PEM):", ORG_CERTIFICATE_PEM_STR, height=250, disabled=True)
        st.markdown(f"**Sujeto:** {ORG_CERTIFICATE.subject.rfc4514_string()}")
        st.markdown(f"**Emisor:** {ORG_CERTIFICATE.issuer.rfc4514_string()}")
        st.markdown(f"**Número de Serie:** {ORG_CERTIFICATE.serial_number}")
        st.markdown(f"**Válido Desde (UTC):** {ORG_CERTIFICATE.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')}")
        st.markdown(f"**Válido Hasta (UTC):** {ORG_CERTIFICATE.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        st.error(f"No se pudo cargar la información del certificado de la organización: {e}")

