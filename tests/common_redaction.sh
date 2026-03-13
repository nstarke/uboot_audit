#!/bin/sh

scrub_sensitive_stream() {
	_in_pem_block=0
	while IFS= read -r line || [ -n "$line" ]; do
		lower_line="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"

		# Suppress PEM blocks in their entirety (public keys, EK certificates, etc.)
		case "$lower_line" in
			*"-----begin "*)
				printf '[REDACTED PEM BLOCK]\n'
				_in_pem_block=1
				continue
				;;
			*"-----end "*)
				_in_pem_block=0
				continue
				;;
		esac
		if [ "$_in_pem_block" -eq 1 ]; then
			continue
		fi

		case "$lower_line" in
			*efi-var*|*efi_vars*|*efivars*)
				printf '[REDACTED EFI VARS]\n'
				continue
				;;
		esac

		printf '%s\n' "$line" | sed -E \
			-e 's/(data_hex=)[0-9A-Fa-f]+/\1<REDACTED>/g' \
			-e 's/(([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])[[:space:]]*[:=][[:space:]]*)[^[:space:],;"}]+/\1<REDACTED>/g' \
			-e 's/(([?&]([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]))=)[^&[:space:]]+/\1<REDACTED>/g' \
			-e 's/"data_hex"[[:space:]]*:[[:space:]]*"[^"]*"/"data_hex":"<REDACTED>"/g' \
			-e 's/"([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])"[[:space:]]*:[[:space:]]*"[^"]*"/"\1":"<REDACTED>"/g' \
			-e 's/0x[0-9A-Fa-f]{20,}/<REDACTED>/g' \
			-e 's/([Nn][Aa][Mm][Ee][[:space:]]*:[[:space:]]*)([0-9A-Fa-f]{20,})/\1<REDACTED>/g' \
			-e 's/"([Nn][Aa][Mm][Ee])"[[:space:]]*:[[:space:]]*"[0-9A-Fa-f]{20,}"/"\1":"<REDACTED>"/g' \
			-e 's/([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn][[:space:]]+[Pp][Oo][Ll][Ii][Cc][Yy][[:space:]]*:[[:space:]]*)([0-9A-Fa-f]+)/\1<REDACTED>/g' \
			-e 's/([Aa][Uu][Tt][Hh][[:space:]]*:[[:space:]]*)([^[:space:]]+)/\1<REDACTED>/g' \
			-e 's/([Ss][Hh][Aa][0-9]+[[:space:]]*:[[:space:]]*[0-9]+[[:space:]]*:[[:space:]]*)0x[0-9A-Fa-f]+/\1<REDACTED>/g'
	done
}
