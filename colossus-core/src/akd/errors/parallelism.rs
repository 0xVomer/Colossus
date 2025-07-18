/// The errors thrown by parallel code
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum ParallelismError {
    /// A tokio task join error
    JoinErr(String),
}

impl std::error::Error for ParallelismError {}
impl std::fmt::Display for ParallelismError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JoinErr(err_string) => {
                write!(f, "Failed to join tokio task {err_string}")
            },
        }
    }
}
