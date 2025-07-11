fn main() {
     println!("cargo:rustc-link-search=native=/opt/homebrew/opt/gmp/lib");
     println!("cargo:rustc-link-lib=gmp");
}
