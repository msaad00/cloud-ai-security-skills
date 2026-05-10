{{/* Common labels and naming for the webhook-receiver chart. */}}
{{- define "webhook-receiver.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "webhook-receiver.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "webhook-receiver.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "webhook-receiver.selectorLabels" -}}
app.kubernetes.io/name: webhook-receiver
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
