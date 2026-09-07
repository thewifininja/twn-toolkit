# RADIUS EAP testing is temporarily disabled

The toolkit currently supports PAP and CHAP authentication tests. PEAP/MSCHAPv2
and EAP-TLS testing are disabled in both the web interface and the backend API.
Installing `eapol_test`, changing PATH, submitting an older form, or invoking the
Python EAP entry point does not re-enable them. Saved RADIUS server, credential,
and attribute profiles remain available for supported tests.

The previously used upstream program takes the RADIUS shared secret in its `-s`
process argument. Output redaction and private temporary configuration files do
not protect that argument from local process inspection. Inspection of the
published wpa_supplicant 2.12 `eapol_test.c` confirmed no supported shared-secret
file/stdin alternative in that implementation. The unsafe invocation has been
removed rather than retained behind a runtime opt-in.

Re-enabling requires a reviewed implementation that accepts the secret through a
protected input channel, supported installation on the intended platforms, and
end-to-end checks for process arguments, logs, temporary files, cleanup, and
certificate validation. A wrapper that eventually invokes the same `-s` argument
is insufficient. Source history retains the old implementation for reference.

This affects the RADIUS authentication test tool. Pi enterprise Wi-Fi connection
configuration uses a separate OS networking integration and remains available.
Existing PAP/CHAP-only automation/API validation does not accept EAP protocols.

Deploy the updated code and restart the serving workers on each instance to
activate backend disablement. A new template with an old loaded process is not a
complete deployment. Historical results and saved profiles are not deleted.
