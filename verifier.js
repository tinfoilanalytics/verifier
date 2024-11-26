function updateLinks() {
    let repo = document.getElementById("repo").value;
    let digest = document.getElementById("digest").value;
    let domain = document.getElementById("domain").value;

    let bundleURL = "https://api.github.com/repos/" + repo + "/attestations/sha256:" + digest;
    let attestationURL = `https://${domain}/.well-known/nitro-attestation`;

    let bundleLink = document.getElementById("bundleLink");
    let attestationLink = document.getElementById("attestationLink");

    bundleLink.href = bundleURL;
    bundleLink.textContent = bundleURL;
    
    attestationLink.href = attestationURL;
    attestationLink.textContent = attestationURL;
}

function verify() {
    let repo = document.getElementById("repo").value;
    let digest = document.getElementById("digest").value;
    let domain = document.getElementById("domain").value;
    let log = document.getElementById("log");
    log.innerText = "";

    updateLinks();

    function addLog(message) {
        let timestamp = new Date().toLocaleString();
        log.innerText += `${timestamp} - ${message}\n`;
    }

    let bundleURL = document.getElementById("bundleLink").href;
    let attestationURL = document.getElementById("attestationLink").href;

    addLog(`Verifying ${domain} against EIF digest ${digest}`);
    addLog("Loading WASM verifier");
    
    const go = new Go();
    WebAssembly.instantiateStreaming(fetch("tinfoil-verifier.wasm"), go.importObject).then((result) => {
        go.run(result.instance);
        addLog("WASM verifier loaded");

        addLog("Fetching sigstore attestation bundle from GitHub");
        let sigstorePromise = fetch(bundleURL)
            .catch(error => {
                addLog("Failed to fetch attestation bundle from Sigstore: " + error);
                addLog("Verification failed");
                throw error;
            })
            .then(response => {
                if (response.status !== 200) {
                    let error = `Failed to fetch attestation bundle from Sigstore: ${response.status}`;
                    addLog(error);
                    throw new Error(error);
                }
                return response.json();
            })
            .then(data => {
                let bundle = data.attestations[0].bundle;
                addLog("Verifying sigstore signature");
                let sigstoreMeasurements = JSON.parse(verifySigstore(digest, JSON.stringify(bundle), repo));
                addLog("Sigstore PCR0: " + sigstoreMeasurements.PCR0);
                addLog("Sigstore PCR1: " + sigstoreMeasurements.PCR1);
                addLog("Sigstore PCR2: " + sigstoreMeasurements.PCR2);
                return sigstoreMeasurements;
            });

        addLog("Fetching nitro attestation");
        let nitroPromise = fetch(attestationURL)
            .catch(error => {
                addLog("Failed to fetch nitro attestation: " + error);
                addLog("Verification failed");
                throw error;
            })
            .then(response => {
                if (response.status !== 201) {
                    let error = `Failed to fetch nitro attestation: ${response.status}`;
                    addLog(error);
                    throw new Error(error);
                }
                return response.json();
            })
            .then(nitroAttestation => {
                let nitroMeasurements = JSON.parse(verifyNitro(nitroAttestation));
                addLog("Nitro PCR0: " + nitroMeasurements.PCR0);
                addLog("Nitro PCR1: " + nitroMeasurements.PCR1);
                addLog("Nitro PCR2: " + nitroMeasurements.PCR2);
                return nitroMeasurements;
            });

        // Wait for both to finish and print both
        Promise.all([sigstorePromise, nitroPromise])
            .then(([sigstoreMeasurements, nitroMeasurements]) => {
                let failed = false;
                for (let i = 0; i < 3; i++) {
                    let sigstorePCR = sigstoreMeasurements["PCR" + i];
                    let nitroPCR = nitroMeasurements["PCR" + i];

                    if (sigstorePCR !== nitroPCR) {
                        addLog(`PCR${i} mismatch`);
                        failed = true;
                    } else {
                        addLog(`PCR${i} match`);
                    }
                }

                if (failed) {
                    addLog("Verification failed");
                } else {
                    addLog("Verification successful! ✅");
                }
            })
            .catch(error => {
                addLog("Verification failed: " + error);
            });
    });
}

window.addEventListener("load", function () {
    // Update links when any input changes
    document.getElementById("repo").addEventListener("input", updateLinks);
    document.getElementById("digest").addEventListener("input", updateLinks);
    document.getElementById("domain").addEventListener("input", updateLinks);
    
    verify();
});
