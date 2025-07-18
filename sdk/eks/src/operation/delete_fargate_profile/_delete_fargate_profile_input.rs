// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteFargateProfileInput {
    /// <p>The name of your cluster.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Fargate profile to delete.</p>
    pub fargate_profile_name: ::std::option::Option<::std::string::String>,
}
impl DeleteFargateProfileInput {
    /// <p>The name of your cluster.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>The name of the Fargate profile to delete.</p>
    pub fn fargate_profile_name(&self) -> ::std::option::Option<&str> {
        self.fargate_profile_name.as_deref()
    }
}
impl DeleteFargateProfileInput {
    /// Creates a new builder-style object to manufacture [`DeleteFargateProfileInput`](crate::operation::delete_fargate_profile::DeleteFargateProfileInput).
    pub fn builder() -> crate::operation::delete_fargate_profile::builders::DeleteFargateProfileInputBuilder {
        crate::operation::delete_fargate_profile::builders::DeleteFargateProfileInputBuilder::default()
    }
}

/// A builder for [`DeleteFargateProfileInput`](crate::operation::delete_fargate_profile::DeleteFargateProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteFargateProfileInputBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) fargate_profile_name: ::std::option::Option<::std::string::String>,
}
impl DeleteFargateProfileInputBuilder {
    /// <p>The name of your cluster.</p>
    /// This field is required.
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// <p>The name of the Fargate profile to delete.</p>
    /// This field is required.
    pub fn fargate_profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fargate_profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Fargate profile to delete.</p>
    pub fn set_fargate_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fargate_profile_name = input;
        self
    }
    /// <p>The name of the Fargate profile to delete.</p>
    pub fn get_fargate_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.fargate_profile_name
    }
    /// Consumes the builder and constructs a [`DeleteFargateProfileInput`](crate::operation::delete_fargate_profile::DeleteFargateProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_fargate_profile::DeleteFargateProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_fargate_profile::DeleteFargateProfileInput {
            cluster_name: self.cluster_name,
            fargate_profile_name: self.fargate_profile_name,
        })
    }
}
