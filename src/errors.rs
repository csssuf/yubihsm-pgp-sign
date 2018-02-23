error_chain! {
    links {
        Yubihsm(::yubihsm::Error, ::yubihsm::ErrorKind);
    }

    foreign_links {
        Io(::std::io::Error);
        Time(::std::time::SystemTimeError);
    }
}
