//go:build js && wasm
// +build js,wasm

package main

import (
	_ "embed"
	"encoding/base64"
	"syscall/js"

	"github.com/blocky/nitrite"

	"github.com/tinfoilanalytics/verifier/pkg/models"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

// curl -o trusted_root.json https://tuf-repo-cdn.sigstore.dev/targets/4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c.trusted_root.json
//
//go:embed trusted_root.json
var trustedRootBytes []byte

func verifySigstore() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		digest := args[0].String()
		bundleBytes := []byte(args[1].String())
		repo := args[2].String()

		sigstoreMeasurements, err := sigstore.VerifyAttestedMeasurements(
			trustedRootBytes,
			bundleBytes,
			digest,
			repo,
		)
		if err != nil {
			panic(err)
		}

		return sigstoreMeasurements.String()
	})
}

func verifyNitro() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		attDocBytes, err := base64.StdEncoding.DecodeString(args[0].String())
		if err != nil {
			panic(err)
		}

		att, err := nitrite.Verify(attDocBytes, nitrite.VerifyOptions{})
		if err != nil {
			panic(err)
		}
		return models.MeasurementFromDoc(att.Document).String()
	})
}

func main() {
	js.Global().Set("verifySigstore", verifySigstore())
	js.Global().Set("verifyNitro", verifyNitro())
	<-make(chan struct{})
}
