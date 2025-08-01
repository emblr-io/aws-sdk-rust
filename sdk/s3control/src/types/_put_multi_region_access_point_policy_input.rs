// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container for the information associated with a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutMultiRegionAccessPoint.html">PutMultiRegionAccessPoint</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutMultiRegionAccessPointPolicyInput {
    /// <p>The name of the Multi-Region Access Point associated with the request.</p>
    pub name: ::std::string::String,
    /// <p>The policy details for the <code>PutMultiRegionAccessPoint</code> request.</p>
    pub policy: ::std::string::String,
}
impl PutMultiRegionAccessPointPolicyInput {
    /// <p>The name of the Multi-Region Access Point associated with the request.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The policy details for the <code>PutMultiRegionAccessPoint</code> request.</p>
    pub fn policy(&self) -> &str {
        use std::ops::Deref;
        self.policy.deref()
    }
}
impl PutMultiRegionAccessPointPolicyInput {
    /// Creates a new builder-style object to manufacture [`PutMultiRegionAccessPointPolicyInput`](crate::types::PutMultiRegionAccessPointPolicyInput).
    pub fn builder() -> crate::types::builders::PutMultiRegionAccessPointPolicyInputBuilder {
        crate::types::builders::PutMultiRegionAccessPointPolicyInputBuilder::default()
    }
}

/// A builder for [`PutMultiRegionAccessPointPolicyInput`](crate::types::PutMultiRegionAccessPointPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutMultiRegionAccessPointPolicyInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
}
impl PutMultiRegionAccessPointPolicyInputBuilder {
    /// <p>The name of the Multi-Region Access Point associated with the request.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Multi-Region Access Point associated with the request.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the Multi-Region Access Point associated with the request.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The policy details for the <code>PutMultiRegionAccessPoint</code> request.</p>
    /// This field is required.
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The policy details for the <code>PutMultiRegionAccessPoint</code> request.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The policy details for the <code>PutMultiRegionAccessPoint</code> request.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// Consumes the builder and constructs a [`PutMultiRegionAccessPointPolicyInput`](crate::types::PutMultiRegionAccessPointPolicyInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::PutMultiRegionAccessPointPolicyInputBuilder::name)
    /// - [`policy`](crate::types::builders::PutMultiRegionAccessPointPolicyInputBuilder::policy)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::PutMultiRegionAccessPointPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PutMultiRegionAccessPointPolicyInput {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building PutMultiRegionAccessPointPolicyInput",
                )
            })?,
            policy: self.policy.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "policy",
                    "policy was not specified but it is required when building PutMultiRegionAccessPointPolicyInput",
                )
            })?,
        })
    }
}
