# Reviewed recovery import proposals only. Planning previews imports; only a separately authorized apply could persist them.

import {
  to = google_secret_manager_secret_iam_member.runtime["api_password"]
  id = "projects/clipforgebeta2/secrets/clipforge-int-pg-app-password roles/secretmanager.secretAccessor serviceAccount:clipforge-api-int@clipforgebeta2.iam.gserviceaccount.com"
}

import {
  to = google_secret_manager_secret_iam_member.runtime["worker_password"]
  id = "projects/clipforgebeta2/secrets/clipforge-int-pg-app-password roles/secretmanager.secretAccessor serviceAccount:clipforge-worker-int@clipforgebeta2.iam.gserviceaccount.com"
}

import {
  to = google_secret_manager_secret_iam_member.runtime["migrate_password"]
  id = "projects/clipforgebeta2/secrets/clipforge-int-pg-migrator-password roles/secretmanager.secretAccessor serviceAccount:clipforge-migrate-int@clipforgebeta2.iam.gserviceaccount.com"
}

import {
  to = google_secret_manager_secret_iam_member.version_publisher["app_password"]
  id = "projects/clipforgebeta2/secrets/clipforge-int-pg-app-password roles/secretmanager.secretVersionAdder serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
}

import {
  to = google_secret_manager_secret_iam_member.version_publisher["migrator_password"]
  id = "projects/clipforgebeta2/secrets/clipforge-int-pg-migrator-password roles/secretmanager.secretVersionAdder serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
}
