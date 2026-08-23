use std::path::PathBuf;

#[cfg(target_os = "openbsd")]
fn configure_libclang() {
  if std::env::var_os("LIBCLANG_PATH").is_some() {
    return;
  }

  let mut llvm_dirs = std::fs::read_dir("/usr/local")
    .into_iter()
    .flatten()
    .flatten()
    .map(|entry| entry.path())
    .filter(|path| {
      path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("llvm"))
    })
    .collect::<Vec<_>>();
  llvm_dirs.sort();
  llvm_dirs.reverse();

  for llvm_dir in llvm_dirs {
    let lib_dir = llvm_dir.join("lib");
    let has_libclang = std::fs::read_dir(&lib_dir)
      .into_iter()
      .flatten()
      .flatten()
      .any(|entry| {
        entry
          .file_name()
          .to_string_lossy()
          .starts_with("libclang.so")
      });
    if has_libclang {
      std::env::set_var("LIBCLANG_PATH", lib_dir);
      return;
    }
  }
}

fn main() {
  println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
  #[cfg(target_os = "openbsd")]
  configure_libclang();

  println!("cargo:rerun-if-changed=vendor/ubpf/CMakeLists.txt");
  println!("cargo:rerun-if-changed=vendor/ubpf/cmake");
  println!("cargo:rerun-if-changed=vendor/ubpf/vm");

  let dst = cmake::Config::new("vendor/ubpf")
    .define("UBPF_SKIP_EXTERNAL", "ON")
    .build_target("ubpf")
    .build();

  println!(
    "cargo:rustc-link-search=native={}",
    dst.join("build/lib").display()
  );
  println!("cargo:rustc-link-lib=static=ubpf");

  // `wrapper.h` pulls in the internal header as well as the public one, so the
  // differential harness can reach `ubpf_translate_function_x86_64` and
  // `ubpf_translate_function_arm64` directly. Both are linked into the library
  // on every host; only `ubpf_create()`'s function-pointer selection is
  // `#if`-gated, so either backend can be byte-diffed from either host.
  println!("cargo:rerun-if-changed=wrapper.h");
  let bindings = bindgen::Builder::default()
    .header("wrapper.h")
    .clang_arg(format!("-I{}", dst.join("build/vm").display()))
    .clang_arg("-Ivendor/ubpf/vm")
    .clang_arg("-Ivendor/ubpf/vm/inc")
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    .generate()
    .expect("Unable to generate bindings");

  let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
  bindings
    .write_to_file(out_path.join("ubpf_bindings.rs"))
    .expect("Couldn't write bindings!");
}
