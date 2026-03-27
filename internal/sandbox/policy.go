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

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version          string   `yaml:"version"`
	AllowedEndpoints []string `yaml:"allowed_endpoints"`
	DeniedEndpoints  []string `yaml:"denied_endpoints"`
	AllowedSkills    []string `yaml:"allowed_skills"`
	DeniedSkills     []string `yaml:"denied_skills"`
	Permissions      []string `yaml:"permissions"`
}

func DefaultPolicy() *Policy {
	return &Policy{
		Version: "1",
	}
}

func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return nil, fmt.Errorf("sandbox: read policy %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("sandbox: parse policy %s: %w", path, err)
	}
	return &p, nil
}

func (p *Policy) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("sandbox: create policy dir: %w", err)
	}

	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("sandbox: marshal policy: %w", err)
	}

	return os.WriteFile(path, data, 0o600)
}

func (p *Policy) DenyEndpoint(endpoint string) bool {
	for _, e := range p.DeniedEndpoints {
		if e == endpoint {
			return false
		}
	}
	p.DeniedEndpoints = append(p.DeniedEndpoints, endpoint)

	filtered := p.AllowedEndpoints[:0]
	for _, e := range p.AllowedEndpoints {
		if e != endpoint {
			filtered = append(filtered, e)
		}
	}
	p.AllowedEndpoints = filtered
	return true
}

func (p *Policy) AllowEndpoint(endpoint string) bool {
	filtered := p.DeniedEndpoints[:0]
	for _, e := range p.DeniedEndpoints {
		if e != endpoint {
			filtered = append(filtered, e)
		}
	}
	changed := len(filtered) != len(p.DeniedEndpoints)
	p.DeniedEndpoints = filtered

	for _, e := range p.AllowedEndpoints {
		if e == endpoint {
			return changed
		}
	}
	p.AllowedEndpoints = append(p.AllowedEndpoints, endpoint)
	return true
}

func (p *Policy) DenySkill(skill string) bool {
	for _, s := range p.DeniedSkills {
		if s == skill {
			return false
		}
	}
	p.DeniedSkills = append(p.DeniedSkills, skill)

	filtered := p.AllowedSkills[:0]
	for _, s := range p.AllowedSkills {
		if s != skill {
			filtered = append(filtered, s)
		}
	}
	p.AllowedSkills = filtered
	return true
}

func (p *Policy) AllowSkill(skill string) bool {
	filtered := p.DeniedSkills[:0]
	for _, s := range p.DeniedSkills {
		if s != skill {
			filtered = append(filtered, s)
		}
	}
	changed := len(filtered) != len(p.DeniedSkills)
	p.DeniedSkills = filtered

	for _, s := range p.AllowedSkills {
		if s == skill {
			return changed
		}
	}
	p.AllowedSkills = append(p.AllowedSkills, skill)
	return true
}
