// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMembershipItem {
    /// <p></p>
    pub membership_id: ::std::string::String,
    /// <p></p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub region: ::std::option::Option<crate::types::AwsRegion>,
    /// <p></p>
    pub membership_arn: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub membership_status: ::std::option::Option<crate::types::MembershipStatus>,
}
impl ListMembershipItem {
    /// <p></p>
    pub fn membership_id(&self) -> &str {
        use std::ops::Deref;
        self.membership_id.deref()
    }
    /// <p></p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p></p>
    pub fn region(&self) -> ::std::option::Option<&crate::types::AwsRegion> {
        self.region.as_ref()
    }
    /// <p></p>
    pub fn membership_arn(&self) -> ::std::option::Option<&str> {
        self.membership_arn.as_deref()
    }
    /// <p></p>
    pub fn membership_status(&self) -> ::std::option::Option<&crate::types::MembershipStatus> {
        self.membership_status.as_ref()
    }
}
impl ListMembershipItem {
    /// Creates a new builder-style object to manufacture [`ListMembershipItem`](crate::types::ListMembershipItem).
    pub fn builder() -> crate::types::builders::ListMembershipItemBuilder {
        crate::types::builders::ListMembershipItemBuilder::default()
    }
}

/// A builder for [`ListMembershipItem`](crate::types::ListMembershipItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMembershipItemBuilder {
    pub(crate) membership_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<crate::types::AwsRegion>,
    pub(crate) membership_arn: ::std::option::Option<::std::string::String>,
    pub(crate) membership_status: ::std::option::Option<crate::types::MembershipStatus>,
}
impl ListMembershipItemBuilder {
    /// <p></p>
    /// This field is required.
    pub fn membership_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_membership_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_id = input;
        self
    }
    /// <p></p>
    pub fn get_membership_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_id
    }
    /// <p></p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p></p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p></p>
    pub fn region(mut self, input: crate::types::AwsRegion) -> Self {
        self.region = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_region(mut self, input: ::std::option::Option<crate::types::AwsRegion>) -> Self {
        self.region = input;
        self
    }
    /// <p></p>
    pub fn get_region(&self) -> &::std::option::Option<crate::types::AwsRegion> {
        &self.region
    }
    /// <p></p>
    pub fn membership_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_membership_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_arn = input;
        self
    }
    /// <p></p>
    pub fn get_membership_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_arn
    }
    /// <p></p>
    pub fn membership_status(mut self, input: crate::types::MembershipStatus) -> Self {
        self.membership_status = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_membership_status(mut self, input: ::std::option::Option<crate::types::MembershipStatus>) -> Self {
        self.membership_status = input;
        self
    }
    /// <p></p>
    pub fn get_membership_status(&self) -> &::std::option::Option<crate::types::MembershipStatus> {
        &self.membership_status
    }
    /// Consumes the builder and constructs a [`ListMembershipItem`](crate::types::ListMembershipItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`membership_id`](crate::types::builders::ListMembershipItemBuilder::membership_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ListMembershipItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ListMembershipItem {
            membership_id: self.membership_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "membership_id",
                    "membership_id was not specified but it is required when building ListMembershipItem",
                )
            })?,
            account_id: self.account_id,
            region: self.region,
            membership_arn: self.membership_arn,
            membership_status: self.membership_status,
        })
    }
}
