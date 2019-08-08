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
