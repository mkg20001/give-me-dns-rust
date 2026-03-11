{ rustPlatform
, lib
, pkg-config
}:

rustPlatform.buildRustPackage {
  pname = "give-me-dns";
  version = "0.1.0";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [];

  meta = with lib; {
    description = "Temporary DNS names for IPv6 addresses";
    homepage = "https://github.com/mkg20001/give-me-dns";
    license = licenses.mit;
    maintainers = [];
  };
}
