# License boundaries

VIRP core and its C, Python, and Go interfaces retain Apache-2.0; LICENSE is
unchanged. Copies accompany include/, api/, and implementations/go/ so the
license travels with these interfaces. Existing copyright notices are preserved.

src/third_party/cJSON.c and cJSON.h retain their embedded MIT license and
attribution. src/third_party/README retains upstream attribution.
src/third_party/pkcs11_min.h cites OASIS PKCS#11 v2.40 but supplies no separate
license or copyright notice. Its provenance/terms need confirmation; it is left
unchanged without a newly assigned SPDX identifier.

Historical deployment files, test vectors, fixtures, and signed evidence are
unchanged and retain their existing provenance and notices. Source SPDX headers
do not replace third-party or historical terms.
