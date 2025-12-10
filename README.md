Bechmarking code for Reachability and SAST

## Requests
# CVE-2023-32681
requests@2.24.0
requests.get
requests.api.request
requests.sessions.Session.request
requests.sessions.Session.send
requests.sessions.Session.get_adapter

# CVE-2024-35195
requests@2.31.0
requests.api..post()
requests.api..request()
requests.sessions.Session.request()
requests.sessions.Session.send()
requests.adapters.HTTPAdapter.send()
Requests `Session` object does not verify requests after making first request with verify=False

# CVE-2025-47273
huggingface-llm-test..load_and_use_model()
transformers@4.57.1
transformers.modeling_utils.PreTrainedModel.to()
transformers.feature_extraction_utils.BatchFeature.to()
transformers.utils.import_utils..requires_backends()
transformers.video_utils..load_video()
setuptools@65.5.0
setuptools.package_index.PackageIndex.download()
setuptools.package_index.PackageIndex._download_url()
setuptools has a path traversal vulnerability in PackageIndex.download that leads to Arbitrary File Write

# CVE-2024-5206
scikit-learn@0.20.1
sklearn.feature_extraction.text.CountVectorizer._limit_features()
scikit-learn sensitive data leakage vulnerability

# CVE-2022-28347
django-cachalot@2.4.0
cachalot.utils.._get_tables()
django@3.2.5
django.db.models.sql.compiler.SQLCompiler.as_sql()
django.db.backends.postgersql.operations.DatabaseOperations.explain_query_prefix()

# CVE-2025-66221
flask@3.1.2
flask.app.Flask.__init__()
flask.app.Flask.send_static_file()
flask.helpers..send_from_directory()
werkzeug@3.1.3
werkzeug.utils..send_from_directory()
werkzeug.security..safe_join()