package bastion

import (
	"context"
	"strconv"
	"time"

	gcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/client"
	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/api/compute/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Reconcile(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "reconcile")

	gcpClient, err := a.getGCPClient(ctx, bastion)
	if err != nil {
		return errors.Wrap(err, "failed to create GCP client")
	}

	opt, err := DetermineOptions(ctx, bastion, cluster)
	if err != nil {
		return errors.Wrap(err, "failed to setup GCP options")
	}

	opt.FirewallName, err = ensureFirewallRule(ctx, logger, gcpClient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to ensure firewall rule")
	}

	endpoints, err := ensureBastionInstance(ctx, logger, gcpClient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to ensure bastion instance")
	}

	if !endpoints.Ready() {
		return &ctrlerror.RequeueAfterError{
			// requeue rather soon, so that the user (most likely gardenctl eventually)
			// doesn't have to wait too long for the public endpoint to become available
			RequeueAfter: 5 * time.Second,
			Cause:        errors.New("bastion instance has no public/private endpoints yet"),
		}
	}

	return controller.TryUpdateStatus(ctx, retry.DefaultBackoff, a.Client(), bastion, func() error {
		bastion.Status.Ingress = *endpoints.public
		return nil
	})

}

func ensureFirewallRule(ctx context.Context, logger logr.Logger, gcpclient gcpclient.Interface, opt *Options) (string, error) {
	firewallName, err := getFirewallRule(ctx, gcpclient, opt)
	if err != nil {
		return "", errors.Wrap(err, "could not find firewall rule")
	}

	// create firewall if it doesn't exist yet
	if firewallName == "" {
		firewallName, err := createFirewallRule(ctx, gcpclient, opt)
		if err != nil {
			return "", errors.Wrap(err, "could not create firewall rule")
		}
		return firewallName, nil
	}

	return firewallName, nil
}

func getFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (string, error) {
	firewall, err := gcpclient.Firewalls().Get(opt.ProjectID, opt.FirewallName).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	if firewall.Name == "" {
		return "", nil
	}

	return firewall.Name, nil
}

func createFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (string, error) {
	rb := &compute.Firewall{
		Allowed:     []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{strconv.Itoa(SSHPort)}}},
		Description: "Allowed all traffic",
		Direction:   "INGRESS",
		TargetTags:  []string{"gardenctl"},
		Name:        opt.FirewallName,
		Network:     "projects/" + opt.ProjectID + "/global/networks/" + opt.Shoot.Name,
		//TODO source Ranges
		SourceRanges: []string{"119.-.-.-/32"},
	}
	resp, err := gcpclient.Firewalls().Insert(opt.ProjectID, rb).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	return resp.Name, nil
}

func ensureBastionInstance(ctx context.Context, logger logr.Logger, gcpclient gcpclient.Interface, opt *Options) (*bastionEndpoints, error) {
	// check if the instance already exists and has an IP
	endpoints, err := getInstanceEndpoints(ctx, gcpclient, opt)
	if err != nil { // could not check for instance
		return nil, errors.Wrap(err, "failed to check for GCP Bastion instance")
	}

	// instance exists, though it may not be ready yet
	if endpoints != nil {
		return endpoints, nil
	}

	// prepare to create a new instance
	//TODO add instance value input
	// input := ""
	logger.Info("Running new bastion instance")
	//TODO add insert interface to create new instance
	// _, err = gcpclient.Instances().insert(ctx, input)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "failed to run instance")
	// }
	return getInstanceEndpoints(ctx, gcpclient, opt)
}

func getInstanceEndpoints(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (*bastionEndpoints, error) {
	instance, err := gcpclient.Instances().Get(opt.ProjectID, opt.Zone, opt.BastionInstanceName).Context(ctx).Do()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get GCP instance")
	}

	if instance == nil {
		return nil, nil
	}

	endpoints := &bastionEndpoints{}

	if ingress := addressToIngress(&instance.Name, &instance.NetworkInterfaces[0].NetworkIP); ingress != nil {
		endpoints.private = ingress
	}

	if ingress := addressToIngress(&instance.Name, &instance.NetworkInterfaces[0].AccessConfigs[0].NatIP); ingress != nil {
		endpoints.public = ingress
	}

	return endpoints, nil
}

// bastionEndpoints collects the endpoints the bastion host provides; the
// private endpoint is important for opening a port on the worker node
// security group to allow SSH from that node, the public endpoint is where
// the enduser connects to to establish the SSH connection.
type bastionEndpoints struct {
	private *corev1.LoadBalancerIngress
	public  *corev1.LoadBalancerIngress
}

// Ready returns true if both public and private interfaces each have either
// an IP or a hostname or both.
func (be *bastionEndpoints) Ready() bool {
	return be != nil && IngressReady(be.private) && IngressReady(be.public)
}

// IngressReady returns true if either an IP or a hostname or both are set.
func IngressReady(ingress *corev1.LoadBalancerIngress) bool {
	return ingress != nil && (ingress.Hostname != "" || ingress.IP != "")
}

// addressToIngress converts the IP address into a
// corev1.LoadBalancerIngress resource. If both arguments are nil, then
// nil is returned.
func addressToIngress(hostName *string, ipAddress *string) *corev1.LoadBalancerIngress {
	var ingress *corev1.LoadBalancerIngress

	if ipAddress != nil {
		ingress = &corev1.LoadBalancerIngress{}
		if hostName != nil {
			ingress.Hostname = *hostName
		}

		if ipAddress != nil {
			ingress.IP = *ipAddress
		}
	}

	return ingress
}
