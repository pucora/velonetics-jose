package mux

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/velonetics/go-auth0/v2"
	veloneticsjose "github.com/velonetics/velonetics-jose/v2"
	"github.com/velonetics/lura/v2/config"
	"github.com/velonetics/lura/v2/logging"
	"github.com/velonetics/lura/v2/proxy"
	muxlura "github.com/velonetics/lura/v2/router/mux"
)

func HandlerFactory(hf muxlura.HandlerFactory, paramExtractor muxlura.ParamExtractor, logger logging.Logger, rejecterF veloneticsjose.RejecterFactory) muxlura.HandlerFactory {
	return TokenSignatureValidator(TokenSigner(hf, paramExtractor, logger), logger, rejecterF)
}

func TokenSigner(hf muxlura.HandlerFactory, paramExtractor muxlura.ParamExtractor, logger logging.Logger) muxlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		signerCfg, signer, err := veloneticsjose.NewSigner(cfg, nil)
		if err == veloneticsjose.ErrNoSignerCfg {
			logger.Info("JOSE: signer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error("JOSE: unable to create the signer for the endpoint", cfg.Endpoint)
			logger.Error(err.Error())
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: signer enabled for the endpoint", cfg.Endpoint)

		return func(w http.ResponseWriter, r *http.Request) {
			proxyReq := muxlura.NewRequestBuilder(paramExtractor)(r, cfg.QueryString, cfg.HeadersToPass)
			ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error("proxy response error:", err.Error())
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			if response == nil {
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			if err := veloneticsjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(err.Error())
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				w.Header().Set(k, v[0])
			}

			err = jsonRender(w, response)
			if err != nil {
				logger.Error("render answer error:", err.Error())
			}
		}
	}
}

var emptyResponse = []byte("{}")

func jsonRender(w http.ResponseWriter, response *proxy.Response) error {
	w.Header().Set("Content-Type", "application/json")

	if response == nil {
		_, err := w.Write(emptyResponse)
		return err
	}

	w.WriteHeader(response.Metadata.StatusCode)

	js, err := json.Marshal(response.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	_, err = w.Write(js)
	return err
}

func TokenSignatureValidator(hf muxlura.HandlerFactory, logger logging.Logger, rejecterF veloneticsjose.RejecterFactory) muxlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		if rejecterF == nil {
			rejecterF = new(veloneticsjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		signatureConfig, err := veloneticsjose.GetSignatureConfig(cfg)
		if err == veloneticsjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		validator, err := veloneticsjose.NewValidator(signatureConfig, FromCookie, FromHeader)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		var aclCheck func(string, map[string]interface{}, []string) bool

		if signatureConfig.RolesKeyIsNested && strings.Contains(signatureConfig.RolesKey, ".") && signatureConfig.RolesKey[:4] != "http" {
			aclCheck = veloneticsjose.CanAccessNested
		} else {
			aclCheck = veloneticsjose.CanAccess
		}

		var scopesMatcher func(string, map[string]interface{}, []string) bool

		if len(signatureConfig.Scopes) > 0 && signatureConfig.ScopesKey != "" {
			if signatureConfig.ScopesMatcher == "all" {
				scopesMatcher = veloneticsjose.ScopesAllMatcher
			} else {
				scopesMatcher = veloneticsjose.ScopesAnyMatcher
			}
		} else {
			scopesMatcher = veloneticsjose.ScopesDefaultMatcher
		}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		return func(w http.ResponseWriter, r *http.Request) {
			token, err := validator.ValidateRequest(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(r, token, &claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if rejecter.Reject(claims) {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			if !aclCheck(signatureConfig.RolesKey, claims, signatureConfig.Roles) {
				http.Error(w, "", http.StatusForbidden)
				return
			}

			if !scopesMatcher(signatureConfig.ScopesKey, claims, signatureConfig.Scopes) {
				http.Error(w, "", http.StatusForbidden)
				return
			}

			propagateHeaders(cfg, signatureConfig.PropagateClaimsToHeader, signatureConfig.PropagateClaimsPreserveArray, claims, r, logger)

			handler(w, r)
		}
	}
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}

func FromHeader(header string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if header == "" {
		header = "Authorization"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		raw := r.Header.Get(header)
		if len(raw) > 7 && strings.EqualFold(raw[0:7], "BEARER ") {
			raw = raw[7:]
		}
		if raw == "" {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(raw)
	}
}

func propagateHeaders(
	cfg *config.EndpointConfig,
	propagationCfg [][]string,
	propagationPreserveArrays bool,
	claims map[string]interface{},
	r *http.Request,
	logger logging.Logger,
) {
	if len(propagationCfg) > 0 {
		if !propagationPreserveArrays {
			headersToPropagate, err := veloneticsjose.CalculateHeadersToPropagate(propagationCfg, claims)
			if err != nil {
				logger.Warning(fmt.Sprintf("JOSE: header propagations error for %s: %s", cfg.Endpoint, err.Error()))
			}
			for k, v := range headersToPropagate {
				// Set header value - replaces existing one
				r.Header.Set(k, v)
			}
			return
		}

		headersToPropagate, err := veloneticsjose.CalculateArrayHeadersToPropagate(propagationCfg, claims)
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: header propagations error for %s: %s", cfg.Endpoint, err.Error()))
		}
		for k, v := range headersToPropagate {
			r.Header[textproto.CanonicalMIMEHeaderKey(k)] = v
		}
	}
}
