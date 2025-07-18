// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for <code>DeleteComputeEnvironment</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteComputeEnvironmentInput {
    /// <p>The name or Amazon Resource Name (ARN) of the compute environment to delete.</p>
    pub compute_environment: ::std::option::Option<::std::string::String>,
}
impl DeleteComputeEnvironmentInput {
    /// <p>The name or Amazon Resource Name (ARN) of the compute environment to delete.</p>
    pub fn compute_environment(&self) -> ::std::option::Option<&str> {
        self.compute_environment.as_deref()
    }
}
impl DeleteComputeEnvironmentInput {
    /// Creates a new builder-style object to manufacture [`DeleteComputeEnvironmentInput`](crate::operation::delete_compute_environment::DeleteComputeEnvironmentInput).
    pub fn builder() -> crate::operation::delete_compute_environment::builders::DeleteComputeEnvironmentInputBuilder {
        crate::operation::delete_compute_environment::builders::DeleteComputeEnvironmentInputBuilder::default()
    }
}

/// A builder for [`DeleteComputeEnvironmentInput`](crate::operation::delete_compute_environment::DeleteComputeEnvironmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteComputeEnvironmentInputBuilder {
    pub(crate) compute_environment: ::std::option::Option<::std::string::String>,
}
impl DeleteComputeEnvironmentInputBuilder {
    /// <p>The name or Amazon Resource Name (ARN) of the compute environment to delete.</p>
    /// This field is required.
    pub fn compute_environment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.compute_environment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the compute environment to delete.</p>
    pub fn set_compute_environment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.compute_environment = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the compute environment to delete.</p>
    pub fn get_compute_environment(&self) -> &::std::option::Option<::std::string::String> {
        &self.compute_environment
    }
    /// Consumes the builder and constructs a [`DeleteComputeEnvironmentInput`](crate::operation::delete_compute_environment::DeleteComputeEnvironmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_compute_environment::DeleteComputeEnvironmentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_compute_environment::DeleteComputeEnvironmentInput {
            compute_environment: self.compute_environment,
        })
    }
}
