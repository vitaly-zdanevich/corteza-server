package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	authService "github.com/cortezaproject/corteza-server/auth"
	authHandlers "github.com/cortezaproject/corteza-server/auth/handlers"
	"github.com/cortezaproject/corteza-server/auth/saml"
	authSettings "github.com/cortezaproject/corteza-server/auth/settings"
	autService "github.com/cortezaproject/corteza-server/automation/service"
	cmpService "github.com/cortezaproject/corteza-server/compose/service"
	cmpEvent "github.com/cortezaproject/corteza-server/compose/service/event"
	fdrService "github.com/cortezaproject/corteza-server/federation/service"
	fedService "github.com/cortezaproject/corteza-server/federation/service"
	"github.com/cortezaproject/corteza-server/pkg/actionlog"
	"github.com/cortezaproject/corteza-server/pkg/auth"
	"github.com/cortezaproject/corteza-server/pkg/corredor"
	"github.com/cortezaproject/corteza-server/pkg/eventbus"
	"github.com/cortezaproject/corteza-server/pkg/healthcheck"
	"github.com/cortezaproject/corteza-server/pkg/http"
	"github.com/cortezaproject/corteza-server/pkg/locale"
	"github.com/cortezaproject/corteza-server/pkg/logger"
	"github.com/cortezaproject/corteza-server/pkg/mail"
	"github.com/cortezaproject/corteza-server/pkg/messagebus"
	"github.com/cortezaproject/corteza-server/pkg/monitor"
	"github.com/cortezaproject/corteza-server/pkg/options"
	"github.com/cortezaproject/corteza-server/pkg/provision"
	"github.com/cortezaproject/corteza-server/pkg/rbac"
	"github.com/cortezaproject/corteza-server/pkg/scheduler"
	"github.com/cortezaproject/corteza-server/pkg/seeder"
	"github.com/cortezaproject/corteza-server/pkg/sentry"
	"github.com/cortezaproject/corteza-server/pkg/websocket"
	"github.com/cortezaproject/corteza-server/store"
	sysService "github.com/cortezaproject/corteza-server/system/service"
	sysEvent "github.com/cortezaproject/corteza-server/system/service/event"
	"github.com/cortezaproject/corteza-server/system/types"
	"go.uber.org/zap"
	gomail "gopkg.in/mail.v2"
)

const (
	bootLevelWaiting = iota
	bootLevelSetup
	bootLevelStoreInitialized
	bootLevelProvisioned
	bootLevelServicesInitialized
	bootLevelActivated
)

// Setup configures all required services
func (app *CortezaApp) Setup() (err error) {
	app.Log = logger.Default()

	if app.lvl >= bootLevelSetup {
		// Are basics already set-up?
		return nil
	}

	{
		// Raise warnings about experimental parts that are enabled
		log := app.Log.WithOptions(zap.WithCaller(false))

		if app.Opt.Federation.Enabled {
			log.Warn("Record Federation is still in EXPERIMENTAL phase")
		}

		if app.Opt.SCIM.Enabled {
			log.Warn("Support for SCIM protocol is still in EXPERIMENTAL phase")
		}

		if app.Opt.DB.IsSQLite() {
			log.Warn("You're using SQLite as a storage backend")
			log.Warn("Should be used only for testing")
			log.Warn("You may experience unstability and data loss")
		}
	}

	hcd := healthcheck.Defaults()
	hcd.Add(scheduler.Healthcheck, "Scheduler")
	hcd.Add(mail.Healthcheck, "Mail")
	hcd.Add(corredor.Healthcheck, "Corredor")

	if err = sentry.Init(app.Opt.Sentry); err != nil {
		return fmt.Errorf("could not initialize Sentry: %w", err)
	}

	// Use Sentry right away to handle any panics
	// that might occur inside auth, mail setup...
	defer sentry.Recover()

	{
		var (
			localeLog = zap.NewNop()
		)

		if app.Opt.Locale.Log {
			localeLog = app.Log
		}

		if languages, err := locale.Service(localeLog, app.Opt.Locale); err != nil {
			return err
		} else {
			locale.SetGlobal(languages)
		}
	}

	// set base path for links&routes in auth server
	authHandlers.BasePath = app.Opt.HTTPServer.BaseUrl

	auth.SetupDefault(app.Opt.Auth.Secret, app.Opt.Auth.Expiry)

	mail.SetupDialer(
		app.Opt.SMTP.Host,
		app.Opt.SMTP.Port,
		app.Opt.SMTP.User,
		app.Opt.SMTP.Pass,
		app.Opt.SMTP.From,

		// Apply TLS configuration
		func(d *gomail.Dialer) {
			if d.TLSConfig == nil {
				d.TLSConfig = &tls.Config{ServerName: d.Host}
			}

			if app.Opt.SMTP.TlsInsecure {
				d.TLSConfig.InsecureSkipVerify = true
			}

			if app.Opt.SMTP.TlsServerName != "" {
				d.TLSConfig.ServerName = app.Opt.SMTP.TlsServerName
			}
		},
	)

	http.SetupDefaults(
		app.Opt.HTTPClient.HttpClientTimeout,
		app.Opt.HTTPClient.ClientTSLInsecure,
	)

	monitor.Setup(app.Log, app.Opt.Monitor)

	if app.Opt.Eventbus.SchedulerEnabled {
		scheduler.Setup(app.Log, eventbus.Service(), app.Opt.Eventbus.SchedulerInterval)
		scheduler.Service().OnTick(
			sysEvent.SystemOnInterval(),
			sysEvent.SystemOnTimestamp(),
			cmpEvent.ComposeOnInterval(),
			cmpEvent.ComposeOnTimestamp(),
		)
	} else {
		app.Log.Debug("eventbus scheduler disabled (EVENTBUS_SCHEDULER_ENABLED=false)")
	}

	if err = corredor.Setup(app.Log, app.Opt.Corredor); err != nil {
		return err
	}

	{
		// load only setup even if disabled, so we can fail gracefuly
		// on queue push
		messagebus.Setup(options.Messagebus(), app.Log)

		if !app.Opt.Messagebus.Enabled {
			app.Log.Debug("messagebus disabled (MESSAGEBUS_ENABLED=false)")
		}
	}

	app.lvl = bootLevelSetup
	return
}

// InitStore initializes store backend(s) and runs upgrade procedures
func (app *CortezaApp) InitStore(ctx context.Context) (err error) {
	if app.lvl >= bootLevelStoreInitialized {
		// Is store already initialised?
		return nil
	} else if err = app.Setup(); err != nil {
		// Initialize previous level
		return err
	}

	// Do not re-initialize store
	// This will make integration test setup a bit more painless
	if app.Store == nil {
		defer sentry.Recover()

		app.Store, err = store.Connect(ctx, app.Opt.DB.DSN)
		if err != nil {
			return err
		}
	}

	app.Log.Info("running store update")

	if !app.Opt.Upgrade.Always {
		app.Log.Info("store upgrade skipped (UPGRADE_ALWAYS=false)")
	} else {
		ctx = actionlog.RequestOriginToContext(ctx, actionlog.RequestOrigin_APP_Upgrade)

		// If not explicitly set (UPGRADE_DEBUG=true) suppress logging in upgrader
		log := zap.NewNop()
		if app.Opt.Upgrade.Debug {
			log = app.Log.Named("store.upgrade")
			log.Info("store upgrade running in debug mode (UPGRADE_DEBUG=true)")
		} else {
			app.Log.Info("store upgrade running (to enable upgrade debug logging set UPGRADE_DEBUG=true)")
		}

		if err = store.Upgrade(ctx, log, app.Store); err != nil {
			return err
		}

		// @todo refactor this to make more sense and put it where it belongs
		{
			var set types.SettingValueSet
			set, _, err = store.SearchSettings(ctx, app.Store, types.SettingsFilter{Prefix: "auth.external"})
			if err != nil {
				return err
			}

			err = set.Walk(func(old *types.SettingValue) error {
				if strings.HasSuffix(old.Name, ".redirect-url") {
					// remove obsolete redirect-url
					if err = store.DeleteSetting(ctx, app.Store, old); err != nil {
						return err
					}

					return nil
				}

				if strings.Contains(old.Name, ".provider.gplus.") {
					var new = *old
					new.Name = strings.Replace(new.Name, "provider.gplus.", "provider.google.", 1)

					log.Info("renaming settings", zap.String("old", old.Name), zap.String("new", new.Name))

					if err = store.CreateSetting(ctx, app.Store, &new); err != nil {
						if store.ErrNotUnique != err {
							return err
						}
					}

					if err = store.DeleteSetting(ctx, app.Store, old); err != nil {
						return err
					}
				}

				return nil
			})

			if err != nil {
				return err
			}
		}

	}

	app.lvl = bootLevelStoreInitialized
	return nil
}

// Provision instance with configuration and settings
// by importing preset configurations and running autodiscovery procedures
func (app *CortezaApp) Provision(ctx context.Context) (err error) {
	if app.lvl >= bootLevelProvisioned {
		return
	}

	if err = app.InitStore(ctx); err != nil {
		return err
	}

	if err = app.initSystemEntities(ctx); err != nil {
		return
	}

	{
		// register temporary RBAC with bypass roles
		// this is needed because envoy relies on availability of access-control
		//
		// @todo envoy should be decoupled from RBAC and import directly into store,
		//       w/o using any access control

		var (
			ac  = rbac.NewService(zap.NewNop(), app.Store)
			acr = make([]*rbac.Role, 0)
		)
		for _, r := range auth.ProvisionUser().Roles() {
			acr = append(acr, rbac.BypassRole.Make(r, auth.BypassRoleHandle))
		}
		ac.UpdateRoles(acr...)
		rbac.SetGlobal(ac)
		defer rbac.SetGlobal(nil)
	}

	if !app.Opt.Provision.Always {
		app.Log.Debug("provisioning skipped (PROVISION_ALWAYS=false)")
	} else {
		defer sentry.Recover()

		ctx = actionlog.RequestOriginToContext(ctx, actionlog.RequestOrigin_APP_Provision)
		ctx = auth.SetIdentityToContext(ctx, auth.ProvisionUser())

		if err = provision.Run(ctx, app.Log, app.Store, app.Opt.Provision, app.Opt.Auth); err != nil {
			return err
		}
	}

	app.lvl = bootLevelProvisioned
	return
}

// InitServices initializes all services used
func (app *CortezaApp) InitServices(ctx context.Context) (err error) {
	if app.lvl >= bootLevelServicesInitialized {
		return nil
	}

	if err := app.Provision(ctx); err != nil {
		return err
	}

	if err = app.initSystemEntities(ctx); err != nil {
		return
	}

	app.WsServer = websocket.Server(app.Log, app.Opt.Websocket)

	ctx = actionlog.RequestOriginToContext(ctx, actionlog.RequestOrigin_APP_Init)
	defer sentry.Recover()

	if err = corredor.Service().Connect(ctx); err != nil {
		return
	}

	if rbac.Global() == nil {
		log := zap.NewNop()
		if app.Opt.RBAC.Log {
			log = app.Log
		}

		//Initialize RBAC subsystem
		ac := rbac.NewService(log, app.Store)

		// and (re)load rules from the storage backend
		ac.Reload(ctx)

		rbac.SetGlobal(ac)
	}

	if app.Opt.Messagebus.Enabled {
		// initialize all the queue handlers
		messagebus.Service().Init(ctx, app.Store)
	}

	// Initializes system services
	//
	// Note: this is a legacy approach, all services from all 3 apps
	// will most likely be merged in the future
	err = sysService.Initialize(ctx, app.Log, app.Store, app.WsServer, sysService.Config{
		ActionLog: app.Opt.ActionLog,
		Storage:   app.Opt.ObjStore,
		Template:  app.Opt.Template,
		Auth:      app.Opt.Auth,
		RBAC:      app.Opt.RBAC,
	})

	if err != nil {
		return
	}

	// Initializes automation services
	//
	// Note: this is a legacy approach, all services from all 3 apps
	// will most likely be merged in the future
	err = autService.Initialize(ctx, app.Log, app.Store, app.WsServer, autService.Config{
		ActionLog: app.Opt.ActionLog,
		Workflow:  app.Opt.Workflow,
		Corredor:  app.Opt.Corredor,
	})

	if err != nil {
		return
	}

	// Initializes compose services
	//
	// Note: this is a legacy approach, all services from all 3 apps
	// will most likely be merged in the future
	err = cmpService.Initialize(ctx, app.Log, app.Store, cmpService.Config{
		ActionLog: app.Opt.ActionLog,
		Storage:   app.Opt.ObjStore,
	})

	if err != nil {
		return
	}

	corredor.Service().SetUserFinder(sysService.DefaultUser)
	corredor.Service().SetRoleFinder(sysService.DefaultRole)

	if app.Opt.Federation.Enabled {
		// Initializes federation services
		//
		// Note: this is a legacy approach, all services from all 3 apps
		// will most likely be merged in the future
		err = fdrService.Initialize(ctx, app.Log, app.Store, fdrService.Config{
			ActionLog:  app.Opt.ActionLog,
			Federation: app.Opt.Federation,
		})

		if err != nil {
			return
		}
	}

	// Initializing seeder
	_ = seeder.Seeder(ctx, app.Store, seeder.Faker())

	app.lvl = bootLevelServicesInitialized
	return
}

// Activate start all internal services and watchers
func (app *CortezaApp) Activate(ctx context.Context) (err error) {
	if app.lvl >= bootLevelActivated {
		return
	}

	if err := app.InitServices(ctx); err != nil {
		return err
	}

	ctx = actionlog.RequestOriginToContext(ctx, actionlog.RequestOrigin_APP_Activate)
	defer sentry.Recover()

	// Start scheduler
	if app.Opt.Eventbus.SchedulerEnabled {
		scheduler.Service().Start(ctx)
	}

	// Load corredor scripts & init watcher (script reloader)
	corredor.Service().Load(ctx)
	corredor.Service().Watch(ctx)

	sysService.Watchers(ctx)
	autService.Watchers(ctx)
	cmpService.Watchers(ctx)

	if app.Opt.Federation.Enabled {
		fedService.Watchers(ctx)
	}

	monitor.Watcher(ctx)

	rbac.Global().Watch(ctx)

	if err = sysService.Activate(ctx); err != nil {
		return err
	}

	if err = autService.Activate(ctx); err != nil {
		return err
	}

	if err = cmpService.Activate(ctx); err != nil {
		return err
	}

	if app.AuthService, err = authService.New(ctx, app.Log, app.Store, app.Opt.Auth); err != nil {
		return fmt.Errorf("failed to init auth service: %w", err)
	}

	updateFederationSettings(app.Opt.Federation, sysService.CurrentSettings)
	updateAuthSettings(app.AuthService, sysService.CurrentSettings)
	sysService.DefaultSettings.Register("auth.", func(ctx context.Context, current interface{}, set types.SettingValueSet) {
		appSettings, is := current.(*types.AppSettings)
		if !is {
			return
		}

		updateAuthSettings(app.AuthService, appSettings)
	})

	app.AuthService.Watch(ctx)

	// messagebus reloader and consumer listeners
	if app.Opt.Messagebus.Enabled {

		// set messagebus listener on input channel
		messagebus.Service().Listen(ctx)

		// watch for queue changes and restart on update
		messagebus.Service().Watch(ctx, app.Store)
	}

	app.lvl = bootLevelActivated
	return nil
}

// Provisions and initializes system roles and users
func (app *CortezaApp) initSystemEntities(ctx context.Context) (err error) {
	if app.systemEntitiesInitialized {
		// make sure we do this once.
		return nil
	}

	app.systemEntitiesInitialized = true

	var (
		uu types.UserSet
		rr types.RoleSet
	)

	// Basic provision for system resources that we need before anything else
	if rr, err = provision.SystemRoles(ctx, app.Log, app.Store); err != nil {
		return
	}

	// Basic provision for system users that we need before anything else
	if uu, err = provision.SystemUsers(ctx, app.Log, app.Store); err != nil {
		return
	}

	// set system users & roles with so that the whole app knows what to use
	auth.SetSystemUsers(uu, rr)
	auth.SetSystemRoles(rr)

	app.Log.Debug(
		"system entities set",
		zap.Uint64s("users", uu.IDs()),
		zap.Uint64s("roles", rr.IDs()),
	)

	return nil
}

func updateAuthSettings(svc authServicer, current *types.AppSettings) {
	as := &authSettings.Settings{
		LocalEnabled:              current.Auth.Internal.Enabled,
		SignupEnabled:             current.Auth.Internal.Signup.Enabled,
		EmailConfirmationRequired: current.Auth.Internal.Signup.EmailConfirmationRequired,
		PasswordResetEnabled:      current.Auth.Internal.PasswordReset.Enabled,
		PasswordCreateEnabled:     current.Auth.Internal.PasswordCreate.Enabled,
		SplitCredentialsCheck:     current.Auth.Internal.SplitCredentialsCheck,
		ExternalEnabled:           current.Auth.External.Enabled,
		MultiFactor: authSettings.MultiFactor{
			TOTP: authSettings.TOTP{
				Enabled:  current.Auth.MultiFactor.TOTP.Enabled,
				Enforced: current.Auth.MultiFactor.TOTP.Enforced,
				Issuer:   current.Auth.MultiFactor.TOTP.Issuer,
			},
			EmailOTP: authSettings.EmailOTP{
				Enabled:  current.Auth.MultiFactor.EmailOTP.Enabled,
				Enforced: current.Auth.MultiFactor.EmailOTP.Enforced,
			},
		},
	}

	for _, p := range current.Auth.External.Providers {
		if p.ValidConfiguration() {
			as.Providers = append(as.Providers, authSettings.Provider{
				Handle:      p.Handle,
				Label:       p.Label,
				IssuerUrl:   p.IssuerUrl,
				Key:         p.Key,
				RedirectUrl: p.RedirectUrl,
				Secret:      p.Secret,
			})
		}
	}

	// SAML
	saml.UpdateSettings(current, as)

	svc.UpdateSettings(as)
}

// Checks if federation is enabled in the options
func updateFederationSettings(opt options.FederationOpt, current *types.AppSettings) {
	current.Federation.Enabled = opt.Enabled
}
