const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("ziggypiai", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_tests = b.addTest(.{
        .root_module = lib,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);

    const oauth_example_module = b.createModule(.{
        .root_source_file = b.path("examples/oauth_login.zig"),
        .target = target,
        .optimize = optimize,
    });
    oauth_example_module.addImport("ziggypiai", lib);

    const oauth_example = b.addExecutable(.{
        .name = "oauth-login-example",
        .root_module = oauth_example_module,
    });

    const run_oauth_example = b.addRunArtifact(oauth_example);
    if (b.args) |args| {
        run_oauth_example.addArgs(args);
    }

    const oauth_example_step = b.step("example-oauth-login", "Run OAuth login example");
    oauth_example_step.dependOn(&run_oauth_example.step);
}
