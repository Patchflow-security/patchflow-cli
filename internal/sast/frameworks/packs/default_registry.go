// Package packs wires all official embedded framework rule packs into a
// single registry. It is the only place that imports every concrete pack,
// which keeps the frameworks package (types/registry/loader/matcher) free of
// import cycles.
package packs

import (
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/angular"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/aspnet"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/django"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/echo"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/express"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/fastapi"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/flask"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/gin"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/graphql"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/laravel"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/nestjs"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/nextjs"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/rails"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/razor"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/react"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/spring"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/springsecurity"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/symfony"
)

// BuildDefaultRegistry creates a Registry populated with all official
// embedded framework packs. This is the canonical registry used by the SAST
// runner and the CLI.
//
// Add new packs here as they are implemented. A pack that is not registered
// here is not selectable by the loader, even if its code exists.
func BuildDefaultRegistry() *frameworks.Registry {
	reg := frameworks.NewRegistry()
	reg.Register(angular.New())
	reg.Register(aspnet.New())
	reg.Register(django.New())
	reg.Register(echo.New())
	reg.Register(express.New())
	reg.Register(fastapi.New())
	reg.Register(flask.New())
	reg.Register(gin.New())
	reg.Register(graphql.New())
	reg.Register(laravel.New())
	reg.Register(nestjs.New())
	reg.Register(nextjs.New())
	reg.Register(rails.New())
	reg.Register(razor.New())
	reg.Register(react.New())
	reg.Register(spring.New())
	reg.Register(springsecurity.New())
	reg.Register(symfony.New())
	return reg
}
