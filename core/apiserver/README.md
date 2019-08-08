# apiserver

路径： cmd/kube-apiserver/apiserver.go
```
func main() {
    rand.Seed(time.Now().UnixNano())

    command := app.NewAPIServerCommand()

    if err := command.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
        os.Exit(1)
    }
}
```

#### app.NewAPIServerCommand
#### 路径:cmd/kube-apiserver/app/server.go 
#### 说明：NewAPIServerCommand creates a *cobra.Command object with default parameters
```
func NewAPIServerCommand() *cobra.Command {
    s := options.NewServerRunOptions()
    cmd := &cobra.Command{
        Use: "kube-apiserver",
        Long: `The Kubernetes API server validates and configures data
for the api objects which include pods, services, replicationcontrollers, and
others. The API Server services REST operations and provides the frontend to the
cluster's shared state through which all other components interact.`,
        RunE: func(cmd *cobra.Command, args []string) error {
            verflag.PrintAndExitIfRequested()
            utilflag.PrintFlags(cmd.Flags())

            // set default options
            completedOptions, err := Complete(s)
            if err != nil {
                return err
            }

            // validate options
            if errs := completedOptions.Validate(); len(errs) != 0 {
                return utilerrors.NewAggregate(errs)
            }

            return Run(completedOptions, genericapiserver.SetupSignalHandler())
        },
    }

    fs := cmd.Flags()
    namedFlagSets := s.Flags()
    verflag.AddFlags(namedFlagSets.FlagSet("global"))
    globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name())
    options.AddCustomGlobalFlags(namedFlagSets.FlagSet("generic"))
    for _, f := range namedFlagSets.FlagSets {
        fs.AddFlagSet(f)
    }

    usageFmt := "Usage:\n  %s\n"
    cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
    cmd.SetUsageFunc(func(cmd *cobra.Command) error {
        fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
        cliflag.PrintSections(cmd.OutOrStderr(), namedFlagSets, cols)
        return nil
    })
    cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
        fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
        cliflag.PrintSections(cmd.OutOrStdout(), namedFlagSets, cols)
    })

    return cmd
}
```
#### s := options.NewServerRunOptions()
#### 路径：cmd/kube-apiserver/app/options/options.go
```
// NewServerRunOptions creates a new ServerRunOptions object with default parameters
func NewServerRunOptions() *ServerRunOptions {
    s := ServerRunOptions{
        GenericServerRunOptions: genericoptions.NewServerRunOptions(),
        Etcd:                    genericoptions.NewEtcdOptions(storagebackend.NewDefaultConfig(kubeoptions.DefaultEtcdPathPrefix, nil)),
        SecureServing:           kubeoptions.NewSecureServingOptions(),
        InsecureServing:         kubeoptions.NewInsecureServingOptions(),
        Audit:                   genericoptions.NewAuditOptions(),
        Features:                genericoptions.NewFeatureOptions(),
        Admission:               kubeoptions.NewAdmissionOptions(),
        Authentication:          kubeoptions.NewBuiltInAuthenticationOptions().WithAll(),
        Authorization:           kubeoptions.NewBuiltInAuthorizationOptions(),
        CloudProvider:           kubeoptions.NewCloudProviderOptions(),
        APIEnablement:           genericoptions.NewAPIEnablementOptions(),

        EnableLogsHandler:      true,
        EventTTL:               1 * time.Hour,
        MasterCount:            1,
        EndpointReconcilerType: string(reconcilers.LeaseEndpointReconcilerType),
        KubeletConfig: kubeletclient.KubeletClientConfig{
            Port:         ports.KubeletPort,
            ReadOnlyPort: ports.KubeletReadOnlyPort,
            PreferredAddressTypes: []string{
                // --override-hostname
                string(api.NodeHostName),

                // internal, preferring DNS if reported
                string(api.NodeInternalDNS),
                string(api.NodeInternalIP),

                // external, preferring DNS if reported
                string(api.NodeExternalDNS),
                string(api.NodeExternalIP),
            },
            EnableHttps: true,
            HTTPTimeout: time.Duration(5) * time.Second,
        },
        ServiceNodePortRange: kubeoptions.DefaultServiceNodePortRange,
    }
    s.ServiceClusterIPRange = kubeoptions.DefaultServiceIPCIDR

    // Overwrite the default for storage data format.
    s.Etcd.DefaultStorageMediaType = "application/vnd.kubernetes.protobuf"

    return &s
}
```

###### GenericServerRunOptions: genericoptions.NewServerRunOptions(),
```
func NewServerRunOptions() *ServerRunOptions {
    defaults := server.NewConfig(serializer.CodecFactory{})
    return &ServerRunOptions{
        MaxRequestsInFlight:         defaults.MaxRequestsInFlight,
        MaxMutatingRequestsInFlight: defaults.MaxMutatingRequestsInFlight,
        RequestTimeout:              defaults.RequestTimeout,
        MinRequestTimeout:           defaults.MinRequestTimeout,
        JSONPatchMaxCopyBytes:       defaults.JSONPatchMaxCopyBytes,
        MaxRequestBodyBytes:         defaults.MaxRequestBodyBytes,
    }
}

```
###### server.NewConfig
###### 路径：staging/src/k8s.io/apiserver/pkg/server/config.go 
```
// NewConfig returns a Config struct with the default values
func NewConfig(codecs serializer.CodecFactory) *Config {
    return &Config{
        Serializer:                  codecs,
        BuildHandlerChainFunc:       DefaultBuildHandlerChain,
        HandlerChainWaitGroup:       new(utilwaitgroup.SafeWaitGroup),
        LegacyAPIGroupPrefixes:      sets.NewString(DefaultLegacyAPIPrefix),
        DisabledPostStartHooks:      sets.NewString(),
        HealthzChecks:               []healthz.HealthzChecker{healthz.PingHealthz, healthz.LogHealthz},
        EnableIndex:                 true,
        EnableDiscovery:             true,
        EnableProfiling:             true,
        EnableMetrics:               true,
        MaxRequestsInFlight:         400,
        MaxMutatingRequestsInFlight: 200,
        RequestTimeout:              time.Duration(60) * time.Second,
        MinRequestTimeout:           1800,
        // 10MB is the recommended maximum client request size in bytes
        // the etcd server should accept. See
        // https://github.com/etcd-io/etcd/blob/release-3.3/etcdserver/server.go#L90.
        // A request body might be encoded in json, and is converted to
        // proto when persisted in etcd. Assuming the upper bound of
        // the size ratio is 10:1, we set 100MB as the largest size
        // increase the "copy" operations in a json patch may cause.
        JSONPatchMaxCopyBytes: int64(100 * 1024 * 1024),
        // 10MB is the recommended maximum client request size in bytes
        // the etcd server should accept. See
        // https://github.com/etcd-io/etcd/blob/release-3.3/etcdserver/server.go#L90.
        // A request body might be encoded in json, and is converted to
        // proto when persisted in etcd. Assuming the upper bound of
        // the size ratio is 10:1, we set 100MB as the largest request
        // body size to be accepted and decoded in a write request.
        MaxRequestBodyBytes:          int64(100 * 1024 * 1024),
        EnableAPIResponseCompression: utilfeature.DefaultFeatureGate.Enabled(features.APIResponseCompression),

        // Default to treating watch as a long-running operation
        // Generic API servers have no inherent long-running subresources
        LongRunningFunc: genericfilters.BasicLongRunningRequestCheck(sets.NewString("watch"), sets.NewString()),
    }
}

const (
    // DefaultLegacyAPIPrefix is where the legacy APIs will be located.
    DefaultLegacyAPIPrefix = "/api"

    // APIGroupPrefix is where non-legacy API group will be located.
    APIGroupPrefix = "/apis"
)

// Config is a structure used to configure a GenericAPIServer.
// Its members are sorted roughly in order of importance for composers.
type Config struct {
    // SecureServing is required to serve https
    SecureServing *SecureServingInfo

    // Authentication is the configuration for authentication
    Authentication AuthenticationInfo

    // Authorization is the configuration for authorization
    Authorization AuthorizationInfo

    // LoopbackClientConfig is a config for a privileged loopback connection to the API server
    // This is required for proper functioning of the PostStartHooks on a GenericAPIServer
    // TODO: move into SecureServing(WithLoopback) as soon as insecure serving is gone
    LoopbackClientConfig *restclient.Config
    // RuleResolver is required to get the list of rules that apply to a given user
    // in a given namespace
    RuleResolver authorizer.RuleResolver
    // AdmissionControl performs deep inspection of a given request (including content)
    // to set values and determine whether its allowed
    AdmissionControl      admission.Interface
    CorsAllowedOriginList []string

    EnableIndex     bool
    EnableProfiling bool
    EnableDiscovery bool
    // Requires generic profiling enabled
    EnableContentionProfiling bool
    EnableMetrics             bool

    DisabledPostStartHooks sets.String

    // Version will enable the /version endpoint if non-nil
    Version *version.Info
    // AuditBackend is where audit events are sent to.
    AuditBackend audit.Backend
    // AuditPolicyChecker makes the decision of whether and how to audit log a request.
    AuditPolicyChecker auditpolicy.Checker
    // ExternalAddress is the host name to use for external (public internet) facing URLs (e.g. Swagger)
    // Will default to a value based on secure serving info and available ipv4 IPs.
    ExternalAddress string
    // BuildHandlerChainFunc allows you to build custom handler chains by decorating the apiHandler.
    BuildHandlerChainFunc func(apiHandler http.Handler, c *Config) (secure http.Handler)
    // HandlerChainWaitGroup allows you to wait for all chain handlers exit after the server shutdown.
    HandlerChainWaitGroup *utilwaitgroup.SafeWaitGroup
    // DiscoveryAddresses is used to build the IPs pass to discovery. If nil, the ExternalAddress is
    // always reported
    DiscoveryAddresses discovery.Addresses
    // The default set of healthz checks. There might be more added via AddHealthzChecks dynamically.
    HealthzChecks []healthz.HealthzChecker
    // LegacyAPIGroupPrefixes is used to set up URL parsing for authorization and for validating requests
    // to InstallLegacyAPIGroup. New API servers don't generally have legacy groups at all.
    LegacyAPIGroupPrefixes sets.String
    // RequestInfoResolver is used to assign attributes (used by admission and authorization) based on a request URL.
    // Use-cases that are like kubelets may need to customize this.
    RequestInfoResolver apirequest.RequestInfoResolver
    // Serializer is required and provides the interface for serializing and converting objects to and from the wire
    // The default (api.Codecs) usually works fine.
    Serializer runtime.NegotiatedSerializer
    // OpenAPIConfig will be used in generating OpenAPI spec. This is nil by default. Use DefaultOpenAPIConfig for "working" defaults.
    OpenAPIConfig *openapicommon.Config

    // RESTOptionsGetter is used to construct RESTStorage types via the generic registry.
    RESTOptionsGetter genericregistry.RESTOptionsGetter

    // If specified, all requests except those which match the LongRunningFunc predicate will timeout
    // after this duration.
    RequestTimeout time.Duration
    // If specified, long running requests such as watch will be allocated a random timeout between this value, and
    // twice this value.  Note that it is up to the request handlers to ignore or honor this timeout. In seconds.
    MinRequestTimeout int
    // The limit on the total size increase all "copy" operations in a json
    // patch may cause.
    // This affects all places that applies json patch in the binary.
    JSONPatchMaxCopyBytes int64
    // The limit on the request body size that would be accepted and decoded in a write request.
    // 0 means no limit.
    MaxRequestBodyBytes int64
    // MaxRequestsInFlight is the maximum number of parallel non-long-running requests. Every further
    // request has to wait. Applies only to non-mutating requests.
    MaxRequestsInFlight int
    // MaxMutatingRequestsInFlight is the maximum number of parallel mutating requests. Every further
    // request has to wait.
    MaxMutatingRequestsInFlight int
    // Predicate which is true for paths of long-running http requests
    LongRunningFunc apirequest.LongRunningRequestCheck
    // EnableAPIResponseCompression indicates whether API Responses should support compression
    // if the client requests it via Accept-Encoding
    EnableAPIResponseCompression bool

    // MergedResourceConfig indicates which groupVersion enabled and its resources enabled/disabled.
    // This is composed of genericapiserver defaultAPIResourceConfig and those parsed from flags.
    // If not specify any in flags, then genericapiserver will only enable defaultAPIResourceConfig.
    MergedResourceConfig *serverstore.ResourceConfig

    //===========================================================================
    // values below here are targets for removal
    //===========================================================================

    // PublicAddress is the IP address where members of the cluster (kubelet,
    // kube-proxy, services, etc.) can reach the GenericAPIServer.
    // If nil or 0.0.0.0, the host's default interface will be used.
    PublicAddress net.IP

    // EquivalentResourceRegistry provides information about resources equivalent to a given resource,
    // and the kind associated with a given resource. As resources are installed, they are registered here.
    EquivalentResourceRegistry runtime.EquivalentResourceRegistry
}

type RecommendedConfig struct {
    Config

    // SharedInformerFactory provides shared informers for Kubernetes resources. This value is set by
    // RecommendedOptions.CoreAPI.ApplyTo called by RecommendedOptions.ApplyTo. It uses an in-cluster client config
    // by default, or the kubeconfig given with kubeconfig command line flag.
    SharedInformerFactory informers.SharedInformerFactory

    // ClientConfig holds the kubernetes client configuration.
    // This value is set by RecommendedOptions.CoreAPI.ApplyTo called by RecommendedOptions.ApplyTo.
    // By default in-cluster client config is used.
    ClientConfig *restclient.Config
}
type SecureServingInfo struct {
    // Listener is the secure server network listener.
    Listener net.Listener

    // Cert is the main server cert which is used if SNI does not match. Cert must be non-nil and is
    // allowed to be in SNICerts.
    Cert *tls.Certificate

    // SNICerts are the TLS certificates by name used for SNI.
    SNICerts map[string]*tls.Certificate

    // ClientCA is the certificate bundle for all the signers that you'll recognize for incoming client certificates
    ClientCA *x509.CertPool

    // MinTLSVersion optionally overrides the minimum TLS version supported.
    // Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
    MinTLSVersion uint16

    // CipherSuites optionally overrides the list of allowed cipher suites for the server.
    // Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
    CipherSuites []uint16

    // HTTP2MaxStreamsPerConnection is the limit that the api server imposes on each client.
    // A value of zero means to use the default provided by golang's HTTP/2 support.
    HTTP2MaxStreamsPerConnection int
}

type AuthenticationInfo struct {
    // APIAudiences is a list of identifier that the API identifies as. This is
    // used by some authenticators to validate audience bound credentials.
    APIAudiences authenticator.Audiences
    // Authenticator determines which subject is making the request
    Authenticator authenticator.Request
    // SupportsBasicAuth indicates that's at least one Authenticator supports basic auth
    // If this is true, a basic auth challenge is returned on authentication failure
    // TODO(roberthbailey): Remove once the server no longer supports http basic auth.
    SupportsBasicAuth bool
}

type AuthorizationInfo struct {
    // Authorizer determines whether the subject is allowed to make the request based only
    // on the RequestURI
    Authorizer authorizer.Authorizer
}

```

```
// ServerRunOptions runs a kubernetes api server.
type ServerRunOptions struct {
    //服务器通用的参数选项
    GenericServerRunOptions *genericoptions.ServerRunOptions
    Etcd                    *genericoptions.EtcdOptions
    SecureServing           *genericoptions.SecureServingOptionsWithLoopback
    InsecureServing         *genericoptions.DeprecatedInsecureServingOptionsWithLoopback
    Audit                   *genericoptions.AuditOptions
    Features                *genericoptions.FeatureOptions
    Admission               *kubeoptions.AdmissionOptions
    Authentication          *kubeoptions.BuiltInAuthenticationOptions
    Authorization           *kubeoptions.BuiltInAuthorizationOptions
    CloudProvider           *kubeoptions.CloudProviderOptions
    APIEnablement           *genericoptions.APIEnablementOptions

    //是否允许pod中容器拥有超级权限
    AllowPrivileged           bool
    EnableLogsHandler         bool
    //时间可以保存时间
    EventTTL                  time.Duration
    //kubelet配置
    KubeletConfig             kubeletclient.KubeletClientConfig
    //服务的节点端口
    KubernetesServiceNodePort int
    MaxConnectionBytesPerSec  int64
    //服务集群IP范围，节点端口范围
    ServiceClusterIPRange     net.IPNet
    ServiceNodePortRange      utilnet.PortRange
    //如果设置，可以使用SSH用户名和私钥对Node访问
    SSHKeyfile                string
    SSHUser                   string

    ProxyClientCertFile string
    ProxyClientKeyFile  string

    EnableAggregatorRouting bool

    MasterCount            int
    EndpointReconcilerType string

    ServiceAccountSigningKeyFile     string
    ServiceAccountIssuer             serviceaccount.TokenGenerator
    ServiceAccountTokenMaxExpiration time.Duration
}
```
#### GenericServerRunOptions *genericoptions.ServerRunOptions
#### 路径：staging/src/k8s.io/apiserver/pkg/server/options/server_runoptions.go
####      genericoptions "k8s.io/apiserver/pkg/server/options"
```
// ServerRunOptions contains the options while running a generic api server.
type ServerRunOptions struct {
    AdvertiseAddress net.IP

    CorsAllowedOriginList       []string
    ExternalHost                string
    MaxRequestsInFlight         int
    MaxMutatingRequestsInFlight int
    RequestTimeout              time.Duration
    MinRequestTimeout           int
    // We intentionally did not add a flag for this option. Users of the
    // apiserver library can wire it to a flag.
    JSONPatchMaxCopyBytes int64
    // The limit on the request body size that would be accepted and
    // decoded in a write request. 0 means no limit.
    // We intentionally did not add a flag for this option. Users of the
    // apiserver library can wire it to a flag.
    MaxRequestBodyBytes       int64
    TargetRAMMB               int
    EnableInfightQuotaHandler bool
}
```

#### NewSecureServingOptions
#### 路径：staging/src/k8s.io/apiserver/pkg/server/options/erving.go
```
type SecureServingOptions struct {
    BindAddress net.IP
    // BindPort is ignored when Listener is set, will serve https even with 0.
    BindPort int
    // BindNetwork is the type of network to bind to - defaults to "tcp", accepts "tcp",
    // "tcp4", and "tcp6".
    BindNetwork string
    // Required set to true means that BindPort cannot be zero.
    Required bool
    // ExternalAddress is the address advertised, even if BindAddress is a loopback. By default this
    // is set to BindAddress if the later no loopback, or to the first host interface address.
    ExternalAddress net.IP

    // Listener is the secure server network listener.
    // either Listener or BindAddress/BindPort/BindNetwork is set,
    // if Listener is set, use it and omit BindAddress/BindPort/BindNetwork.
    Listener net.Listener

    // ServerCert is the TLS cert info for serving secure traffic
    ServerCert GeneratableKeyCert
    // SNICertKeys are named CertKeys for serving secure traffic with SNI support.
    SNICertKeys []cliflag.NamedCertKey
    // CipherSuites is the list of allowed cipher suites for the server.
    // Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
    CipherSuites []string
    // MinTLSVersion is the minimum TLS version supported.
    // Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
    MinTLSVersion string

    // HTTP2MaxStreamsPerConnection is the limit that the api server imposes on each client.
    // A value of zero means to use the default provided by golang's HTTP/2 support.
    HTTP2MaxStreamsPerConnection int
}
type CertKey struct {
    // CertFile is a file containing a PEM-encoded certificate, and possibly the complete certificate chain
    CertFile string
    // KeyFile is a file containing a PEM-encoded private key for the certificate specified by CertFile
    KeyFile string
}

type GeneratableKeyCert struct {
    // CertKey allows setting an explicit cert/key file to use.
    CertKey CertKey

    // CertDirectory specifies a directory to write generated certificates to if CertFile/KeyFile aren't explicitly set.
    // PairName is used to determine the filenames within CertDirectory.
    // If CertDirectory and PairName are not set, an in-memory certificate will be generated.
    CertDirectory string
    // PairName is the name which will be used with CertDirectory to make a cert and key filenames.
    // It becomes CertDirectory/PairName.crt and CertDirectory/PairName.key
    PairName string

    // GeneratedCert holds an in-memory generated certificate if CertFile/KeyFile aren't explicitly set, and CertDirectory/PairName are not set.
    GeneratedCert *tls.Certificate

    // FixtureDirectory is a directory that contains test fixture used to avoid regeneration of certs during tests.
    // The format is:
    // <host>_<ip>-<ip>_<alternateDNS>-<alternateDNS>.crt
    // <host>_<ip>-<ip>_<alternateDNS>-<alternateDNS>.key
    FixtureDirectory string
}

func NewSecureServingOptions() *SecureServingOptions {
    return &SecureServingOptions{
        BindAddress: net.ParseIP("0.0.0.0"),
        BindPort:    443,
        ServerCert: GeneratableKeyCert{
            PairName:      "apiserver",
            CertDirectory: "apiserver.local.config/certificates",
        },
    }
}
```

#### kubeletClientConfig
#### 路径：pkg/kubelet/client/kubelet_client.go
```
type KubeletClientConfig struct {
    // Default port - used if no information about Kubelet port can be found in Node.NodeStatus.DaemonEndpoints.
    Port         uint
    ReadOnlyPort uint
    EnableHttps  bool

    // PreferredAddressTypes - used to select an address from Node.NodeStatus.Addresses
    PreferredAddressTypes []string

    // TLSClientConfig contains settings to enable transport layer security
    restclient.TLSClientConfig

    // Server requires Bearer authentication
    BearerToken string

    // HTTPTimeout is used by the client to timeout http requests to Kubelet.
    HTTPTimeout time.Duration

    // Dial is a custom dialer used for the client
    Dial utilnet.DialFunc
}
```
