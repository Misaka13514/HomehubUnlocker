{
  description = "Build environment for the HomehubUnlocker Xposed module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          # androidenv components are mostly unfree and require accepting the SDK
          # license; allowed here for this build environment only.
          pkgs = import nixpkgs {
            inherit system;
            config = {
              allowUnfree = true;
              android_sdk.accept_license = true;
            };
          };
          android = pkgs.androidenv.composeAndroidPackages {
            platformVersions = [ "34" ];
            buildToolsVersions = [ "34.0.0" ];
            includeEmulator = false;
            includeSystemImages = false;
            includeSources = false;
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.jdk17
              pkgs.zip
            ];
            ANDROID_HOME = "${android.androidsdk}/libexec/android-sdk";
          };
        }
      );
    };
}
