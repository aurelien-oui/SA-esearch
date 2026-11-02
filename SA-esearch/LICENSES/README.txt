Bibliothèques tierces embarquées dans SA-esearch
=============================================================

Chaque bibliothèque est livrée sans modification, avec le texte de sa licence
ci-dessous (et le fichier NOTICE de requests, comme l'exige Apache-2.0).

Bibliothèque            Version      Emplacement             Licence                      Fichier(s)
splunk-sdk (splunklib)  2.1.1        bin/splunklib           Apache-2.0                   splunk-sdk-2.1.1.txt
six (dans splunklib)    1.14.0       bin/splunklib/six.py    MIT                          en-tête de six.py
requests                2.32.4       bin/lib/requests        Apache-2.0                   requests-2.32.4.txt, requests-2.32.4.NOTICE.txt
urllib3                 1.26.20      bin/lib/urllib3         MIT                          urllib3-1.26.20.txt
  dont util/ssl_match_hostname.py et packages/backports/ (repris de la
  bibliothèque standard de Python)  PSF-2.0         urllib3-1.26.20.python-psf.txt
  dont packages/six.py, contrib/securetransport.py,
  contrib/_securetransport/bindings.py           MIT  en-tête de chaque fichier
charset-normalizer      3.3.2        bin/lib/charset_normalizer  MIT                      charset-normalizer-3.3.2.txt
idna                    3.7          bin/lib/idna            BSD-3-Clause                 idna-3.7.txt
certifi                 2026.06.17   bin/lib/certifi         MPL-2.0                      certifi-2026.06.17.txt
deprecation             2.1.0        bin/lib/deprecation.py  Apache-2.0                   deprecation-2.1.0.txt
packaging               26.3         bin/lib/packaging       Apache-2.0 OR BSD-2-Clause   packaging-26.3.txt (+ .APACHE, .BSD)

idna : ses tables (idnadata.py, uts46data.py) sont générées depuis les données
Unicode ; le projet idna ne livre que sa licence BSD-3-Clause.

certifi (MPL-2.0) : code source livré tel quel dans bin/lib/certifi ; également
disponible sur https://pypi.org/project/certifi/2026.6.17/ .
