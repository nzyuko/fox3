/*
Fox3 is a post-exploitation command and control framework.

This file is part of Fox3.
Copyright (C) 2024 Russel Van Tuyl

Fox3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Fox3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Fox3.  If not, see <http://www.gnu.org/licenses/>.
*/

package crypto

import (
	// Standard
	"context"
	"fmt"
	"log/slog"
	"time"

	// 3rd Party
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	// Fox3
	"github.com/nzyuko/fox3/v2/pkg/core"
	"github.com/nzyuko/fox3/v2/pkg/logging"
)

// ValidateJWT validates the provided JSON Web Token
func ValidateJWT(agentJWT string, leeway time.Duration, key []byte) (agentID uuid.UUID, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "JWT", agentJWT, "Leeway", leeway, "Key", key)
	defer slog.Log(context.Background(), logging.LevelTrace, "exiting the function", "Agent", agentID, "Error", err)

	claims := jwt.Claims{}

	// Parse to make sure it is a valid JWT
	nestedToken, err := jwt.ParseSignedAndEncrypted(agentJWT)
	if err != nil {
		err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an error parsing the JWT: %s", err)
		return
	}

	// Decrypt JWT
	token, errToken := nestedToken.Decrypt(key)
	if errToken != nil {
		err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an error decrypting the JWT: %s", errToken)
		return
	}

	// Deserialize the claims and validate the signature
	errClaims := token.Claims(key, &claims)
	if errClaims != nil {
		err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an deserializing the JWT claims: %s", errClaims)
		return
	}

	agentID, err = uuid.Parse(claims.ID)
	if err != nil {
		return
	}

	// Validate claims if leeway is greater than or equal to 0
	if leeway >= 0 {
		err = claims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, leeway)
		if err != nil {
			err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an validating the JWT claims with a leeway of %s: %s", leeway, err)
			slog.Warn(fmt.Sprintf("The JWT claims were not valid for %s: %s", agentID, err), "JWT Claim Expiry", claims.Expiry.Time(), "JWT Claim Issued", claims.IssuedAt.Time())
			return
		}
	} else {
		if core.Verbose {
			slog.Info(fmt.Sprintf("JWT leeway is %s and is less than 0, skipping validation for Agent %s", leeway, agentID))
		}
	}
	// TODO I need to validate other things like token age/expiry
	return
}
// GetJWT returns a JSON Web Token for the provided agent using the interface JWT Key
func GetJWT(agentID uuid.UUID, lifetime time.Duration, key []byte) (string, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "agentID", agentID, "lifetime", lifetime, "key", key)

	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWE encryptor:\r\n%s", encErr)
	}

	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	// This is for when the server hasn't received an AgentInfo struct and doesn't know the agent's lifetime yet or sleep is set to zero
	if lifetime == 0 {
		lifetime = time.Second * 30
	}

	// TODO Add in the rest of the JWT claim info
	cl := jwt.Claims{
		ID:        agentID.String(),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(lifetime)),
	}

	agentJWT, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(cl).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("there was an error serializing the JWT:\r\n%s", err.Error())
	}

	// Parse it to check for errors
	_, errParse := jwt.ParseEncrypted(agentJWT)
	if errParse != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWT:\r\n%s", errParse.Error())
	}
	//logging.Server(fmt.Sprintf("Created authenticated JWT for %s", agentID))
	slog.Debug(fmt.Sprintf("Sending agent %s an authenticated JWT with a lifetime of %v:\r\n%v", agentID.String(), lifetime, agentJWT))
	return agentJWT, nil
}
