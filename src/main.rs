mod checker;
mod dns;
mod domain;
mod logger;
use anyhow::Result;
use clap::Parser;
use domain::DomainEntry;
use log;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use trust_dns_proto::op::Header;
use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::Record;
use trust_dns_proto::rr::RecordType;
use trust_dns_resolver::Name;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::server::ResponseHandler;
use trust_dns_server::server::{Request, RequestHandler, ResponseInfo};
use trust_dns_server::ServerFuture;
mod cache;

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(author="tuxlinuxien@gmail.com",version= "0.1.0", about=None, long_about=None)]
struct Args {
    #[arg(long, default_value_t = 53)]
    port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    interface: String,

    #[arg(long, default_value = "debug", value_parser = ["trace","debug","info","warn","error"])]
    debug: String,

    #[arg(long, default_value_t = false)]
    enable_udp: bool,

    #[arg(long, default_value_t = false)]
    enable_tcp: bool,

    /// file path containing domains that will be blocked
    #[arg(long)]
    ad_file: Option<String>,

    /// file path of your custom hosts
    #[arg(long, default_value = "/etc/hosts")]
    hosts_file: Option<String>,

    #[arg(long, default_value = "8.8.8.8")]
    nameserver: Vec<std::net::IpAddr>,
}

impl Args {
    fn to_level(&self) -> log::LevelFilter {
        match self.debug.as_str() {
            "trace" => log::LevelFilter::Trace,
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            _ => panic!("unsupported"),
        }
    }
}

struct Handler {
    resolver: dns::Resolver,
    domains: Vec<DomainEntry>,
    cache: cache::Cache,
}

impl Handler {
    fn new(resolver: dns::Resolver, domains: Vec<DomainEntry>, cache: cache::Cache) -> Self {
        Self {
            resolver: resolver,
            domains: domains,
            cache: cache,
        }
    }

    fn addr_to_record(&self, ip: IpAddr, name: &str) -> Result<Record> {
        let mut record = Record::new();
        record.set_name(Name::from_utf8(name)?);
        record.set_dns_class(trust_dns_proto::rr::DNSClass::IN);
        match ip {
            IpAddr::V4(ip) => {
                record.set_rr_type(RecordType::A);
                record.set_data(Some(trust_dns_proto::rr::RData::A(ip.into())));
            }
            IpAddr::V6(ip) => {
                record.set_rr_type(RecordType::AAAA);
                record.set_data(Some(trust_dns_proto::rr::RData::AAAA(ip.into())));
            }
        }
        record.set_ttl(3600);
        Ok(record)
    }

    async fn add_to_cache(&self, request: &Request, records: &Vec<Record>) {
        if records.is_empty() {
            return;
        }
        let rt = request.query().query_type();
        let domain = request.query().name().to_string();
        self.cache.insert(&rt, &domain, records).await;
    }

    async fn get_from_cache(&self, request: &Request) -> Option<Vec<Record>> {
        let rt = request.query().query_type();
        let domain = request.query().name().to_string();
        self.cache.get(&rt, &domain).await
    }

    async fn send_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
        code: ResponseCode,
        answers: &[Record],
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(code);
        let builder = MessageResponseBuilder::from_message_request(&request);
        let response = builder.build(header, answers, &[], &[], &[]);
        match responder.send_response(response).await {
            Ok(r) => r,
            Err(_) => header.into(),
        }
    }

    async fn remote_request(&self, request: &Request) -> (ResponseCode, Vec<Record>) {
        let name = request.query().name();
        let qt = request.query().query_type();
        match self.resolver.lookup(name, qt).await {
            Ok(resp) => (
                ResponseCode::NoError,
                resp.record_iter().map(|r| r.clone()).collect(),
            ),
            Err(_e) => (ResponseCode::ServFail, vec![]),
        }
    }

    async fn local_request(&self, request: &Request) -> (ResponseCode, Vec<Record>) {
        let name = request.query().name().to_string();
        let qt = request.query().query_type();
        let ip_check: Box<dyn Fn(&&DomainEntry) -> bool> = match qt {
            RecordType::A => Box::new(|e| e.ip.is_ipv4()),
            RecordType::AAAA => Box::new(|e| e.ip.is_ipv6()),
            _ => return (ResponseCode::NoError, vec![]),
        };
        let records = self
            .domains
            .iter()
            .filter(ip_check)
            .filter(|d| d.name == name)
            .map(|d| self.addr_to_record(d.ip, &d.name))
            .flatten()
            .collect();
        (ResponseCode::NoError, records)
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        responder: R,
    ) -> ResponseInfo {
        let request = match request.query().query_type() {
            RecordType::A => request,
            RecordType::AAAA => request,
            // discard any other type of dns queries.
            _ => {
                return self
                    .send_response(request, responder, ResponseCode::NotImp, &[])
                    .await
            }
        };
        let domain = request.query().name().to_string();
        let qt = request.query().query_type().to_string();
        if let Some(answers) = self.get_from_cache(request).await {
            log::info!("cached response {}:{}", domain, qt);
            return self
                .send_response(request, responder, ResponseCode::NoError, &answers)
                .await;
        }
        let (code, answers) = self.local_request(&request).await;
        self.add_to_cache(request, &answers).await;
        if !answers.is_empty() {
            log::info!("local response {}:{}", domain, qt);
            return self.send_response(request, responder, code, &answers).await;
        }
        // if no local endpoint has been found, we forward the request to the remote
        // dns server and try to fetch a response.
        let (code, answers) = self.remote_request(&request).await;
        self.add_to_cache(request, &answers).await;
        log::info!("remote response {}:{}", domain, qt);
        return self.send_response(request, responder, code, &answers).await;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    logger::init_logger(args.to_level());
    // check
    checker::check_flags(args.enable_tcp, args.enable_udp)?;
    checker::ip_bin().await?;
    // load different domain list
    for ns in args.nameserver.iter() {
        log::info!("using '{}' name server", ns.to_string());
    }
    let adslist = domain::load_domain_list(args.ad_file).await?;
    log::info!("{} domains loaded from the ad file.", adslist.len());
    let hostlist = domain::load_host_list(args.hosts_file).await?;
    log::info!("{} domains loaded from the hosts file.", hostlist.len());

    let domains = [adslist, hostlist].concat();
    let net = format!("{}:{}", args.interface, args.port);

    let cache = cache::new();
    // clean cached entries regularly.
    cache.cleanup();

    let resolver = dns::new(&args.nameserver);
    let handler = Handler::new(resolver, domains, cache);
    let mut server = ServerFuture::new(handler);
    if args.enable_udp {
        log::info!("UDP enabled on {}", &net);
        server.register_socket(UdpSocket::bind(&net).await?);
    }
    if args.enable_tcp {
        log::info!("TCP enabled on {}", &net);
        server.register_listener(TcpListener::bind(&net).await?, TCP_TIMEOUT);
    }
    server.block_until_done().await?;

    Ok(())
}
