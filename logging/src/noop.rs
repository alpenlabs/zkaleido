use std::marker::PhantomData;

/// No-op replacement for `tracing::error!` in zkVM builds.
#[macro_export]
macro_rules! error {
    ($($tt:tt)*) => {{}};
}

/// No-op replacement for `tracing::warn!` in zkVM builds.
#[macro_export]
macro_rules! warn {
    ($($tt:tt)*) => {{}};
}

/// No-op replacement for `tracing::info!` in zkVM builds.
#[macro_export]
macro_rules! info {
    ($($tt:tt)*) => {{}};
}

/// No-op replacement for `tracing::debug!` in zkVM builds.
#[macro_export]
macro_rules! debug {
    ($($tt:tt)*) => {{}};
}

/// No-op replacement for `tracing::trace!` in zkVM builds.
#[macro_export]
macro_rules! trace {
    ($($tt:tt)*) => {{}};
}

/// No-op replacement for `tracing::error_span!` in zkVM builds.
#[macro_export]
macro_rules! error_span {
    ($($tt:tt)*) => {
        $crate::Span::none()
    };
}

/// No-op replacement for `tracing::warn_span!` in zkVM builds.
#[macro_export]
macro_rules! warn_span {
    ($($tt:tt)*) => {
        $crate::Span::none()
    };
}

/// No-op replacement for `tracing::info_span!` in zkVM builds.
#[macro_export]
macro_rules! info_span {
    ($($tt:tt)*) => {
        $crate::Span::none()
    };
}

/// No-op replacement for `tracing::debug_span!` in zkVM builds.
#[macro_export]
macro_rules! debug_span {
    ($($tt:tt)*) => {
        $crate::Span::none()
    };
}

/// No-op replacement for `tracing::trace_span!` in zkVM builds.
#[macro_export]
macro_rules! trace_span {
    ($($tt:tt)*) => {
        $crate::Span::none()
    };
}

/// No-op replacement for `tracing::Span` in zkVM builds.
///
/// Covers the subset of the `tracing::Span` API that callers use to scope work: build one,
/// enter it, or run a closure inside it.
#[derive(Clone, Debug)]
pub struct Span;

impl Span {
    /// Returns a span that does nothing.
    pub fn none() -> Self {
        Self
    }

    /// Returns a span that does nothing. There is never a current span in zkVM builds.
    pub fn current() -> Self {
        Self
    }

    /// Enters the span for as long as the returned guard lives.
    pub fn enter(&self) -> Entered<'_> {
        Entered(PhantomData)
    }

    /// Enters the span and returns a guard that owns it.
    pub fn entered(self) -> EnteredSpan {
        EnteredSpan(self)
    }

    /// Runs `f` inside the span.
    pub fn in_scope<F: FnOnce() -> T, T>(&self, f: F) -> T {
        f()
    }
}

/// No-op replacement for `tracing::span::Entered` in zkVM builds.
#[derive(Debug)]
pub struct Entered<'a>(PhantomData<&'a Span>);

/// No-op replacement for `tracing::span::EnteredSpan` in zkVM builds.
#[derive(Debug)]
pub struct EnteredSpan(Span);

impl EnteredSpan {
    /// Exits the span and returns it.
    pub fn exit(self) -> Span {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_macros_compile() {
        let transaction_id = "tx123";
        let error_code = 42;

        info!("Processing transaction");

        warn!(
            "Transaction {} failed with error code {}",
            transaction_id, error_code
        );

        error!("Critical error: {:?}", ("complex", "data", 123));

        debug!("Debug info: {}", "details");
        trace!("Trace data: {:x}", 255);

        let result = {
            info!("Starting operation");
            "success"
        };
        assert_eq!(result, "success");
    }

    #[test]
    fn test_format_args_validation() {
        warn!("Simple message");
        error!("Message with arg: {}", 42);
        info!("Multiple args: {} and {}", "first", "second");

        debug!(
            "Number: {}, hex: {:x}, debug: {:?}",
            123,
            255,
            vec![1, 2, 3]
        );
    }

    #[test]
    fn test_span_macros_compile() {
        let txid = "tx123";

        let _guard = info_span!("tx", %txid).entered();
        let span = debug_span!("tx", txid);
        let _entered = span.enter();
        let result = trace_span!("op").in_scope(|| 7);
        assert_eq!(result, 7);

        let _ = warn_span!("w").entered().exit();
        let _ = error_span!("e", field = ?txid);
        let _ = Span::current();
    }
}
