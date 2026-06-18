mod app;
pub mod json;

fn main() -> anyhow::Result<()> {
    app::run()
}
