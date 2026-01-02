#[cfg(feature = "logging")]
macro_rules! __zk_log {
    ($level:ident, $($arg:tt)+) => {
        log::$level!($($arg)+);
    };
}

#[cfg(not(feature = "logging"))]
macro_rules! __zk_log {
    ($level:ident, $($arg:tt)+) => {
        let _ = core::format_args!($($arg)+);
        let _level = stringify!($level);
        let _ = _level;
    };
}

macro_rules! zk_log_info {
    ($($arg:tt)+) => {
        __zk_log!(info, $($arg)+);
    };
}

macro_rules! zk_log_warn {
    ($($arg:tt)+) => {
        __zk_log!(warn, $($arg)+);
    };
}

macro_rules! zk_log_debug {
    ($($arg:tt)+) => {
        __zk_log!(debug, $($arg)+);
    };
}
