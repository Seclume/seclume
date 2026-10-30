{{- define "seclume-admission.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "seclume-admission.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "seclume-admission.labels" -}}
app.kubernetes.io/name: {{ include "seclume-admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "seclume-admission.selector" -}}
app.kubernetes.io/name: {{ include "seclume-admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The image, by digest when one is given. */}}
{{- define "seclume-admission.image" -}}
{{- if not .Values.image.repository -}}
{{- fail "image.repository is required: the image deploy/build-image.sh built, pushed to your registry" -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "seclume-admission.service" -}}
{{- printf "%s.%s.svc" (include "seclume-admission.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "seclume-admission.tlsSecret" -}}
{{- if eq .Values.tls.mode "existingSecret" -}}
{{- required "tls.existingSecret names the kubernetes.io/tls secret" .Values.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "seclume-admission.fullname" .) -}}
{{- end -}}
{{- end -}}
