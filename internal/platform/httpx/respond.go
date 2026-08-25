package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
)

const maxRequestBody = 1 << 20

var ErrMalformedBody = errors.New("httpx: request body is missing or malformed")

type problemBody struct {
	Error problemDetail `json:"error"`
}

type problemDetail struct {
	Code string `json:"code"`
}

func JSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		Problem(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(encoded, '\n'))
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return ErrMalformedBody
	}
	if decoder.More() {
		return ErrMalformedBody
	}
	return nil
}

func Problem(w http.ResponseWriter, status int, code string) {
	encoded, err := json.Marshal(problemBody{Error: problemDetail{Code: code}})
	if err != nil {
		http.Error(w, `{"error":{"code":"internal_error"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(encoded, '\n'))
}
