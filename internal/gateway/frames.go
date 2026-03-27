// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "encoding/json"

// RequestFrame is a client → gateway RPC request.
type RequestFrame struct {
	Type   string      `json:"type"`
	ID     string      `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

// ResponseFrame is a gateway → client RPC response.
type ResponseFrame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   *FrameError     `json:"error,omitempty"`
}

// FrameError contains error details from a failed RPC response.
type FrameError struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details,omitempty"`
}

// EventFrame is a gateway → client broadcast event.
type EventFrame struct {
	Type    string          `json:"type"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Seq     *int            `json:"seq,omitempty"`
}

// HelloOK is the payload of a successful connect response.
type HelloOK struct {
	Type     string          `json:"type"`
	Protocol int             `json:"protocol"`
	Features *HelloFeatures  `json:"features,omitempty"`
	Auth     *HelloAuth      `json:"auth,omitempty"`
	Policy   *HelloPolicy    `json:"policy,omitempty"`
}

type HelloFeatures struct {
	Methods []string `json:"methods,omitempty"`
	Events  []string `json:"events,omitempty"`
}

type HelloAuth struct {
	DeviceToken string   `json:"deviceToken,omitempty"`
	Role        string   `json:"role,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

type HelloPolicy struct {
	TickIntervalMs int `json:"tickIntervalMs,omitempty"`
}

// ChallengePayload is the payload of a connect.challenge event.
type ChallengePayload struct {
	Nonce string `json:"nonce"`
	Ts    int64  `json:"ts"`
}

// ToolCallPayload is the payload of a tool_call event.
type ToolCallPayload struct {
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args,omitempty"`
	Status string          `json:"status,omitempty"`
}

// ToolResultPayload is the payload of a tool_result event.
type ToolResultPayload struct {
	Tool     string `json:"tool"`
	Output   string `json:"output,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

// ApprovalRequestPayload is the payload of an exec.approval.requested event.
type ApprovalRequestPayload struct {
	ID            string         `json:"id"`
	SystemRunPlan *SystemRunPlan `json:"systemRunPlan,omitempty"`
}

type SystemRunPlan struct {
	Argv       []string `json:"argv,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	RawCommand string   `json:"rawCommand,omitempty"`
}

// ApprovalResolveParams is the params for exec.approval.resolve RPC.
type ApprovalResolveParams struct {
	ID       string `json:"id"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

// SkillsUpdateParams is the params for skills.update RPC.
type SkillsUpdateParams struct {
	SkillKey string `json:"skillKey"`
	Enabled  bool   `json:"enabled"`
}

// ConfigPatchParams is the legacy params for config.patch RPC (path/value style).
// Note: OpenClaw's config.patch actually expects { raw, baseHash } — see
// ConfigPatchRawParams. This struct is kept for the PatchConfig helper but
// will fail against real OpenClaw gateways.
type ConfigPatchParams struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// ConfigPatchRawParams is the params for config.patch RPC using the raw
// merge format. OpenClaw expects { raw: "<JSON string>", baseHash: "<sha256>" }.
// Unlike config.set (which replaces the entire config), config.patch performs
// a deep merge into the existing config.
type ConfigPatchRawParams struct {
	Raw      string `json:"raw"`
	BaseHash string `json:"baseHash,omitempty"`
}

// configGetResponse extracts the hash and config from a config.get response.
// OpenClaw nests the actual config under a "config" key in the payload.
type configGetResponse struct {
	Hash   string            `json:"hash"`
	Config *configGetInner   `json:"config,omitempty"`
}

type configGetInner struct {
	Plugins *configPlugins `json:"plugins,omitempty"`
}

type configPlugins struct {
	Allow []string `json:"allow,omitempty"`
}

// RawFrame is used for initial JSON parsing to determine frame type.
type RawFrame struct {
	Type  string `json:"type"`
	Event string `json:"event,omitempty"`
}
