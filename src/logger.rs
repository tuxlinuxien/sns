use log::LevelFilter;

pub fn init_logger(level: LevelFilter) {
    let mut builder = env_logger::builder();
    builder.filter(Some("sns"), level);
    builder.init();
}
