rm -R pynacl-wheelhouse tmpwheelhouse #PyNaCl-1.4.0  PyNaCl-1.4.0.tar.gz
#pip install -U pip cffi six
#pip download pynacl --no-deps --no-binary pynacl && tar zxvf PyNaCl*.tar.gz && mkdir tmpwheelhouse
cd PyNaCl-1.4.0
LIBSODIUM_MAKE_ARGS="-j$(nproc)" python3.8 setup.py bdist_wheel && mv dist/PyNaCl*.whl ../tmpwheelhouse
python3.8 -m auditwheel repair tmpwheelhouse/PyNaCl-1.4.0.whl -w wheelhouse/
pip install pynacl --no-index -f wheelhouse/
python3.8 -c "import nacl.signing; key = nacl.signing.SigningKey.generate(); signature = key.sign(b'test'); key.verify_key.verify(signature)"
mkdir pynacl-wheelhouse
mv wheelhouse/PyNaCl*.whl pynacl-wheelhouse/

