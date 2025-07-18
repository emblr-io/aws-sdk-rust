// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIpGroupInput {
    /// <p>The identifier of the IP access control group.</p>
    pub group_id: ::std::option::Option<::std::string::String>,
}
impl DeleteIpGroupInput {
    /// <p>The identifier of the IP access control group.</p>
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
}
impl DeleteIpGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteIpGroupInput`](crate::operation::delete_ip_group::DeleteIpGroupInput).
    pub fn builder() -> crate::operation::delete_ip_group::builders::DeleteIpGroupInputBuilder {
        crate::operation::delete_ip_group::builders::DeleteIpGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteIpGroupInput`](crate::operation::delete_ip_group::DeleteIpGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIpGroupInputBuilder {
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
}
impl DeleteIpGroupInputBuilder {
    /// <p>The identifier of the IP access control group.</p>
    /// This field is required.
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the IP access control group.</p>
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// <p>The identifier of the IP access control group.</p>
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// Consumes the builder and constructs a [`DeleteIpGroupInput`](crate::operation::delete_ip_group::DeleteIpGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_ip_group::DeleteIpGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_ip_group::DeleteIpGroupInput { group_id: self.group_id })
    }
}
