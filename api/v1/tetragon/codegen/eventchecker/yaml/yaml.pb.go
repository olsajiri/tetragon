// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Code generated by protoc-gen-go-tetragon. DO NOT EDIT

package yaml

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"
	eventchecker "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	os "os"
	yaml "sigs.k8s.io/yaml"
	template "text/template"
)

// Metadata contains metadata for the eventchecker definition
type Metadata struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Metadata contains metadata for the eventchecker definition
type EventCheckerConf struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   Metadata              `json:"metadata"`
	Spec       MultiEventCheckerSpec `json:"spec"`
}

// ConfFromSpec creates a new EventCheckerConf from a MultiEventCheckerSpec
func ConfFromSpec(apiVersion, name, description string,
	spec *MultiEventCheckerSpec) (*EventCheckerConf, error) {
	if spec == nil {
		return nil, fmt.Errorf("spec is nil")
	}

	return &EventCheckerConf{
		APIVersion: apiVersion,
		Kind:       "EventChecker",
		Metadata: Metadata{
			Name:        name,
			Description: description,
		},
		Spec: *spec,
	}, nil
}

// ConfFromChecker creates a new EventCheckerConf from a MultiEventChecker
func ConfFromChecker(apiVersion, name, description string,
	checker eventchecker.MultiEventChecker) (*EventCheckerConf, error) {
	spec, err := SpecFromMultiEventChecker(checker)
	if err != nil {
		return nil, err
	}

	return &EventCheckerConf{
		APIVersion: apiVersion,
		Kind:       "EventChecker",
		Metadata: Metadata{
			Name:        name,
			Description: description,
		},
		Spec: *spec,
	}, nil
}

// ReadYaml reads an event checker from yaml
func ReadYaml(data string) (*EventCheckerConf, error) {
	var conf EventCheckerConf

	err := yaml.UnmarshalStrict([]byte(data), &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// ReadYamlFile reads an event checker from a yaml file
func ReadYamlFile(file string) (*EventCheckerConf, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return ReadYaml(string(data))
}

// ReadYamlTemplate reads an event checker template from yaml
func ReadYamlTemplate(text string, data interface{}) (*EventCheckerConf, error) {
	var conf EventCheckerConf

	templ := template.New("checkerYaml")
	templ, err := templ.Parse(text)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	templ.Execute(&buf, data)

	err = yaml.UnmarshalStrict(buf.Bytes(), &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// ReadYamlFileTemplate reads an event checker template from yaml
func ReadYamlFileTemplate(file string, data interface{}) (*EventCheckerConf, error) {
	text, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return ReadYamlTemplate(string(text), data)
}

// WriteYaml writes an event checker to yaml
func (conf *EventCheckerConf) WriteYaml() (string, error) {
	data, err := yaml.Marshal(conf)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// WriteYamlFile writes an event checker to a yaml file
func (conf *EventCheckerConf) WriteYamlFile(file string) error {
	data, err := conf.WriteYaml()
	if err != nil {
		return err
	}

	return os.WriteFile(file, []byte(data), 0o644)
}

type eventCheckerHelper struct {
	ProcessExec       *eventchecker.ProcessExecChecker       `json:"exec,omitempty"`
	ProcessExit       *eventchecker.ProcessExitChecker       `json:"exit,omitempty"`
	ProcessKprobe     *eventchecker.ProcessKprobeChecker     `json:"kprobe,omitempty"`
	ProcessTracepoint *eventchecker.ProcessTracepointChecker `json:"tracepoint,omitempty"`
	ProcessUprobe     *eventchecker.ProcessUprobeChecker     `json:"uprobe,omitempty"`
	Test              *eventchecker.TestChecker              `json:"test,omitempty"`
	ProcessLoader     *eventchecker.ProcessLoaderChecker     `json:"loader,omitempty"`
}

// EventChecker is a wrapper around the EventChecker interface to help unmarshaling
type EventChecker struct {
	eventchecker.EventChecker
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (checker *EventChecker) UnmarshalJSON(b []byte) error {
	var eventChecker eventchecker.EventChecker
	var helper eventCheckerHelper
	if err := yaml.UnmarshalStrict(b, &helper); err != nil {
		return err
	}
	if helper.ProcessExec != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.ProcessExec, eventChecker)
		}
		eventChecker = helper.ProcessExec
	}
	if helper.ProcessExit != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.ProcessExit, eventChecker)
		}
		eventChecker = helper.ProcessExit
	}
	if helper.ProcessKprobe != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.ProcessKprobe, eventChecker)
		}
		eventChecker = helper.ProcessKprobe
	}
	if helper.ProcessTracepoint != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.ProcessTracepoint, eventChecker)
		}
		eventChecker = helper.ProcessTracepoint
	}
	if helper.ProcessUprobe != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.ProcessUprobe, eventChecker)
		}
		eventChecker = helper.ProcessUprobe
	}
	if helper.Test != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.Test, eventChecker)
		}
		eventChecker = helper.Test
	}
	if helper.ProcessLoader != nil {
		if eventChecker != nil {
			return fmt.Errorf("EventChecker: cannot define more than one checker, got %T but already had %T", helper.ProcessLoader, eventChecker)
		}
		eventChecker = helper.ProcessLoader
	}
	checker.EventChecker = eventChecker
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (checker EventChecker) MarshalJSON() ([]byte, error) {
	var helper eventCheckerHelper
	switch c := checker.EventChecker.(type) {
	case *eventchecker.ProcessExecChecker:
		helper.ProcessExec = c
	case *eventchecker.ProcessExitChecker:
		helper.ProcessExit = c
	case *eventchecker.ProcessKprobeChecker:
		helper.ProcessKprobe = c
	case *eventchecker.ProcessTracepointChecker:
		helper.ProcessTracepoint = c
	case *eventchecker.ProcessUprobeChecker:
		helper.ProcessUprobe = c
	case *eventchecker.TestChecker:
		helper.Test = c
	case *eventchecker.ProcessLoaderChecker:
		helper.ProcessLoader = c
	default:
		return nil, fmt.Errorf("EventChecker: unknown checker type %T", c)
	}
	return json.Marshal(helper)
}

// MultiEventCheckerSpec is a YAML spec to define a MultiEventChecker
type MultiEventCheckerSpec struct {
	Ordered bool           `json:"ordered"`
	Checks  []EventChecker `json:"checks"`
}

// IntoMultiEventChecker coerces an event checker from this spec
func (spec *MultiEventCheckerSpec) IntoMultiEventChecker() (eventchecker.MultiEventChecker, error) {
	var checkers []eventchecker.EventChecker

	for _, check := range spec.Checks {
		checkers = append(checkers, check.EventChecker)
	}

	if spec.Ordered {
		return eventchecker.NewOrderedEventChecker(checkers...), nil
	}

	return eventchecker.NewUnorderedEventChecker(checkers...), nil
}

// SpecFromMultiEventChecker coerces a spec from a MultiEventChecker
func SpecFromMultiEventChecker(checker_ eventchecker.MultiEventChecker) (*MultiEventCheckerSpec, error) {
	var spec MultiEventCheckerSpec

	checker, ok := checker_.(interface {
		GetChecks() []eventchecker.EventChecker
	})
	if !ok {
		return nil, fmt.Errorf("Unhandled checker type %T", checker_)
	}

	for _, check := range checker.GetChecks() {
		spec.Checks = append(spec.Checks, EventChecker{check})
	}

	switch checker.(type) {
	case *eventchecker.OrderedEventChecker:
		spec.Ordered = true
	case *eventchecker.UnorderedEventChecker:
		spec.Ordered = false
	default:
		return nil, fmt.Errorf("Unhandled checker type %T", checker)
	}

	return &spec, nil
}
