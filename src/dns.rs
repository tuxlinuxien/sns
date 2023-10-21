use std::net::*;
use trust_dns_resolver::config::*;
use trust_dns_resolver::name_server::GenericConnector;
use trust_dns_resolver::name_server::TokioRuntimeProvider;
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::TokioAsyncResolver;

pub type Resolver = AsyncResolver<GenericConnector<TokioRuntimeProvider>>;

pub fn new(ips: &[IpAddr]) -> Resolver {
    let ns = NameServerConfigGroup::from_ips_clear(ips, 53, true);
    let mut config = ResolverConfig::new();
    ns.iter().for_each(|n| config.add_name_server(n.clone()));

    return TokioAsyncResolver::tokio(config, ResolverOpts::default());
}
